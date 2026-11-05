"""Local ONNX prompt-injection classifier: text in, probability of the attack label out.

A model directory holds one *.onnx file, tokenizer.json and config.json (id2label).
Long text is scored in overlapping windows and the highest window wins, so an
injection buried deep in a document is not averaged away.

Needs onnxruntime, tokenizers and numpy; guard.py itself does not.
"""
import glob
import json
import os
import re
import shutil
import sys
import tempfile

import numpy as np
import onnxruntime as ort
from tokenizers import Tokenizer

POSITIVE = re.compile(r"inject|jailbreak|malicious|unsafe|attack", re.I)


def mapped(onnx):
    """The model re-saved with its weights in a side file, built once in mapped/ beside it.

    ONNX Runtime maps such weights from disk instead of copying them into memory: the 641 MB
    base model then costs ~180 MB of memory instead of ~1 GB, at ~5% slower scoring.
    """
    out = os.path.join(os.path.dirname(onnx), "mapped")
    model = os.path.join(out, "model.onnx")
    if os.path.exists(model) and os.path.getmtime(model) >= os.path.getmtime(onnx):
        return model
    tmp = tempfile.mkdtemp(prefix=".mapped-", dir=os.path.dirname(onnx))
    try:
        so = ort.SessionOptions()
        so.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_BASIC   # saves no CPU-specific fusions
        so.optimized_model_filepath = os.path.join(tmp, "model.onnx")
        so.add_session_config_entry("session.optimized_model_external_initializers_file_name", "model.onnx.data")
        so.add_session_config_entry("session.optimized_model_external_initializers_min_size_in_bytes", "1024")
        ort.InferenceSession(onnx, so, providers=["CPUExecutionProvider"])
        shutil.rmtree(out, ignore_errors=True)
        os.replace(tmp, out)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return model


class Classifier:
    def __init__(self, model_dir, window=None, max_windows=32):
        onnx = glob.glob(os.path.join(model_dir, "*.onnx"))
        if len(onnx) != 1:
            raise ValueError(f"{model_dir} needs exactly one .onnx file, found {len(onnx)}")
        with open(os.path.join(model_dir, "config.json"), encoding="utf-8") as f:
            cfg = json.load(f)
        labels = {int(k): v for k, v in cfg["id2label"].items()}
        self.name = os.path.basename(os.path.normpath(model_dir))
        self.positive = next((i for i, v in labels.items() if POSITIVE.search(v)), max(labels))
        self.window = window or min(cfg.get("max_position_embeddings", 512), 1024)
        # ponytail: long text is cut at max_windows windows (~24k tokens at 1024); raise it if tickets get longer.
        self.max_windows = max_windows
        self.tokenizer = Tokenizer.from_file(os.path.join(model_dir, "tokenizer.json"))
        self.tokenizer.no_padding()
        self.tokenizer.enable_truncation(self.window, stride=self.window // 4)
        try:
            path, so = mapped(onnx[0]), ort.SessionOptions()
            # Prepacking copies every weight into memory, which would undo the mapping.
            so.add_session_config_entry("session.disable_prepacking", "1")
        except Exception as e:   # a read-only or full disk: serve anyway, from the in-memory model
            print(f"{self.name}: no mapped copy ({type(e).__name__}: {e}); loading it into memory", file=sys.stderr)
            path, so = onnx[0], None
        self.session = ort.InferenceSession(path, so, providers=["CPUExecutionProvider"])

    def score(self, text):
        """Highest attack probability over the text's windows, 0..1; `span` keeps that window's character range."""
        first = self.tokenizer.encode(text)
        best, self.span = 0.0, None
        for enc in ([first] + list(first.overflowing))[: self.max_windows]:
            feed = {"input_ids": np.array([enc.ids], dtype=np.int64),
                    "attention_mask": np.array([enc.attention_mask], dtype=np.int64)}
            logits = self.session.run(None, feed)[0][0]
            exp = np.exp(logits - logits.max())
            p = float(exp[self.positive] / exp.sum())
            if self.span is None or p > best:
                chars = [o for o in enc.offsets if o != (0, 0)]   # (0, 0) marks special tokens
                best, self.span = p, (chars[0][0], chars[-1][1]) if chars else None
        return best
