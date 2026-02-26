# bash completion for zk-fuzzer
_zk_fuzzer() {
    local cur prev
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    local global_opts="--config -c --workers -w --seed -s --verbose -v --quiet --dry-run --simple-progress --real-only --profile --kill-existing --list-patterns --help -h"
    local commands="scan run evidence chains preflight validate bins minimize init completions"

    if [[ "${COMP_WORDS[1]}" == "completions" && "${prev}" == "--shell" ]]; then
        COMPREPLY=( $(compgen -W "bash zsh fish" -- "${cur}") )
        return 0
    fi

    if [[ "${COMP_CWORD}" -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "${commands} ${global_opts}" -- "${cur}") )
        return 0
    fi

    case "${COMP_WORDS[1]}" in
        scan)
            COMPREPLY=( $(compgen -W "--family --target-circuit --main-component --framework --iterations -i --timeout -t --resume --corpus-dir --output-suffix --help -h" -- "${cur}") )
            ;;
        run|evidence)
            COMPREPLY=( $(compgen -W "--iterations -i --timeout -t --resume --corpus-dir --help -h" -- "${cur}") )
            ;;
        chains)
            COMPREPLY=( $(compgen -W "--iterations -i --timeout -t --resume --help -h" -- "${cur}") )
            ;;
        preflight)
            COMPREPLY=( $(compgen -W "--setup-keys --help -h" -- "${cur}") )
            ;;
        validate)
            COMPREPLY=( $(compgen -W "--help -h" -- "${cur}") )
            ;;
        bins)
            COMPREPLY=( $(compgen -W "bootstrap --help -h" -- "${cur}") )
            ;;
        minimize)
            COMPREPLY=( $(compgen -W "--output -o --help -h" -- "${cur}") )
            ;;
        init)
            COMPREPLY=( $(compgen -W "--output -o --framework -f --help -h" -- "${cur}") )
            ;;
        completions)
            COMPREPLY=( $(compgen -W "--shell --help -h" -- "${cur}") )
            ;;
        *)
            COMPREPLY=( $(compgen -W "${global_opts}" -- "${cur}") )
            ;;
    esac
}

complete -F _zk_fuzzer zk-fuzzer
