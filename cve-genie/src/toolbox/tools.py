from . import file_ops
from . import command_ops

TOOLS = {
    'get_file': file_ops.get_file,
    'write_to_file': file_ops.write_to_file,
    'execute_ls_command': command_ops.execute_ls_command,
    'execute_linux_command': command_ops.execute_linux_command,
    'set_environment_variable': command_ops.set_environment_variable,
}