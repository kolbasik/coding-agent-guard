# Telemetry, survey and update-check opt-outs for every login shell. Owner: coding-agent-guard's privacy skill.
# Source it from ~/.zprofile through a path that survives plugin updates; the skill's SKILL.md says which.
# DO_NOT_TRACK must be 1, not true: Atlassian's twg CLI reads only "1".
export DO_NOT_TRACK=1
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_NOLOGO=1
export DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE=true
export GH_TELEMETRY=false
export GH_NO_UPDATE_NOTIFIER=1
export GH_NO_EXTENSION_UPDATE_NOTIFIER=1
export HOMEBREW_NO_ANALYTICS=1
export HF_HUB_DISABLE_TELEMETRY=1
export SERENA_USAGE_REPORTING=false
export ORT_DISABLE_TELEMETRY=1
export POWERSHELL_TELEMETRY_OPTOUT=1
export POWERSHELL_UPDATECHECK=Off
export CHECKPOINT_DISABLE=1
export AWS_CLI_SESSION_ID_DISABLED=true
export AWS_CLI_AGENT_TOOLKIT_HINT_DISABLED=true
export npm_config_update_notifier=false
export NO_UPDATE_NOTIFIER=1
export SOPS_DISABLE_VERSION_CHECK=1
export RTK_TELEMETRY_DISABLED=1
export REDOCLY_TELEMETRY=off
export REDOCLY_SUPPRESS_UPDATE_NOTICE=true
