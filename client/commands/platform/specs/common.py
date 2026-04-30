from client.commands.arguments.acmd_registry import (
    ArgumentCommandSpec,
    ArgumentOptionSpec,
)


NETSTAT_ARGUMENT_SPEC = ArgumentCommandSpec(
    name='netstat',
    description='Show TCP/UDP network connections',
    options=[
        ArgumentOptionSpec(
            name='port',
            option_type='int',
            required=False,
            default=None,
            alias='p',
            positional_index=0,
            help_text='Filter by local or remote port',
        ),
        ArgumentOptionSpec(
            name='json',
            option_type='flag',
            required=False,
            default=False,
            help_text='Output as JSON',
        ),
        ArgumentOptionSpec(
            name='help',
            option_type='flag',
            required=False,
            default=False,
            alias='h',
            help_text='Show this help message',
        ),
    ],
    examples=[
        'acmd netstat',
        'acmd netstat 443',
        'acmd netstat --port 443',
        'acmd netstat --port 443 --json',
    ],
)