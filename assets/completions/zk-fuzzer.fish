complete -c zk-fuzzer -f -n "__fish_use_subcommand" -a "scan run evidence chains preflight validate bins minimize init completions"

complete -c zk-fuzzer -l config -s c -d "Path to YAML campaign configuration" -r
complete -c zk-fuzzer -l workers -s w -d "Number of parallel workers" -r
complete -c zk-fuzzer -l seed -s s -d "Seed for reproducibility" -r
complete -c zk-fuzzer -l verbose -s v -d "Verbose output"
complete -c zk-fuzzer -l quiet -d "Minimal output"
complete -c zk-fuzzer -l dry-run -d "Validate config without executing"
complete -c zk-fuzzer -l simple-progress -d "Use simple progress output"
complete -c zk-fuzzer -l real-only -d "Require strict backend availability checks"
complete -c zk-fuzzer -l profile -d "Configuration profile" -a "quick standard deep perf"
complete -c zk-fuzzer -l kill-existing -d "Kill other zk-fuzzer instances on startup"
complete -c zk-fuzzer -l list-patterns -d "List available CVE patterns and exit"

complete -c zk-fuzzer -n "__fish_seen_subcommand_from completions" -l shell -d "Target shell" -a "bash zsh fish"
