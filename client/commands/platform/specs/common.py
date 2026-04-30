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


PS_ARGUMENT_SPEC = ArgumentCommandSpec(
    name='ps',
    description='Show running processes',
    options=[
        ArgumentOptionSpec(
            name='pid',
            option_type='int',
            required=False,
            default=None,
            alias='p',
            positional_index=0,
            help_text='Filter by process id',
        ),
        ArgumentOptionSpec(
            name='name',
            option_type='str',
            required=False,
            default='',
            alias='n',
            help_text='Filter by process name or executable path',
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
        'acmd ps',
        'acmd ps 1234',
        'acmd ps --pid 1234',
        'acmd ps --name python',
        'acmd ps --name python --json',
    ],
)