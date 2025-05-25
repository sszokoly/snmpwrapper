
import asyncio
import os
import subprocess
import shlex
from typing import Optional, Dict, Any, Tuple, Union
import asyncio
from signal import SIGINT, SIGTERM
from typing import Any, Coroutine, TypeVar, Optional, Set, Callable, Any, TypeVar, Tuple
from asyncio import coroutines
from asyncio import events
from asyncio import tasks


def asyncio_run(main, *, debug=None):
    """Execute the coroutine and return the result.

    This function runs the passed coroutine, taking care of
    managing the asyncio event loop and finalizing asynchronous
    generators.

    This function cannot be called when another asyncio event loop is
    running in the same thread.

    If debug is True, the event loop will be run in debug mode.

    This function always creates a new event loop and closes it at the end.
    It should be used as a main entry point for asyncio programs, and should
    ideally only be called once.

    Example:

        async def main():
            await asyncio.sleep(1)
            print('hello')

        asyncio.run(main())
    """
    if events._get_running_loop() is not None:
        raise RuntimeError(
            "asyncio.run() cannot be called from a running event loop")

    if not coroutines.iscoroutine(main):
        raise ValueError("a coroutine was expected, got {!r}".format(main))

    loop = events.new_event_loop()
    try:
        events.set_event_loop(loop)
        if debug is not None:
            loop.set_debug(debug)
        return loop.run_until_complete(main)
    except KeyboardInterrupt:
        print("Got signal: SIGINT, shutting down.")
    finally:
        try:
            _cancel_all_tasks(loop)
            loop.run_until_complete(loop.shutdown_asyncgens())
        finally:
            events.set_event_loop(None)
            loop.close()


def _cancel_all_tasks(loop):
    to_cancel = asyncio.Task.all_tasks()
    if not to_cancel:
        return

    for task in to_cancel:
        task.cancel()

    loop.run_until_complete(tasks.gather(*to_cancel, return_exceptions=True))

    for task in to_cancel:
        if task.cancelled():
            continue
        if task.exception() is not None:
            loop.call_exception_handler({
                'message': 'unhandled exception during asyncio.run() shutdown',
                'exception': task.exception(),
                'task': task,
            })
            

class CommandResult:
    """Container for command execution results"""
    def __init__(self, stdout: str, stderr: str, returncode: int, timed_out: bool = False):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
        self.timed_out = timed_out
        self.success = returncode == 0 and not timed_out

    def __repr__(self):
        return f"CommandResult(returncode={self.returncode}, timed_out={self.timed_out}, success={self.success})"


class CommandTimeoutError(Exception):
    """Raised when command execution times out"""
    def __init__(self, command: str, timeout: float):
        self.command = command
        self.timeout = timeout
        super().__init__(f"Command '{command}' timed out after {timeout} seconds")


class CommandExecutionError(Exception):
    """Raised when command execution fails"""
    def __init__(self, command: str, result: CommandResult):
        self.command = command
        self.result = result
        super().__init__(f"Command '{command}' failed with return code {result.returncode}")


async def run_command(
    command: Union[str, list],
    timeout: Optional[float] = 30.0,
    cwd: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    shell: bool = True,
    encoding: str = 'utf-8'
) -> CommandResult:
    """
    Execute a shell command asynchronously with timeout support.
    
    Args:
        command: Command to execute (string or list of arguments)
        timeout: Timeout in seconds (None for no timeout)
        cwd: Working directory
        env: Environment variables
        shell: Whether to run command in shell
        encoding: Output encoding
        
    Returns:
        CommandResult object with stdout, stderr, returncode, and status info
    """
    try:
        # Prepare command
        if isinstance(command, str) and not shell:
            command = shlex.split(command)
        
        # Create subprocess
        process = await asyncio.create_subprocess_exec(
            *command if isinstance(command, list) else [command],
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=env
        ) if not shell else await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=env
        )
        
        # Wait for completion with timeout
        try:
            stdout_data, stderr_data = await asyncio.wait_for(
                process.communicate(), 
                timeout=timeout
            )
            
            return CommandResult(
                stdout=stdout_data.decode(encoding).strip(),
                stderr=stderr_data.decode(encoding).strip(),
                returncode=process.returncode,
                timed_out=False
            )
            
        except asyncio.TimeoutError:
            # Kill the process if it times out
            try:
                process.kill()
                await process.wait()
            except ProcessLookupError:
                pass  # Process already terminated
            
            return CommandResult(
                stdout='',
                stderr='',
                returncode=-1,
                timed_out=True
            )
            
    except Exception as e:
        # Return error result instead of raising
        return CommandResult(
            stdout='',
            stderr=str(e),
            returncode=-1,
            timed_out=False
        )


async def exec_command(
    command: Union[str, list],
    timeout: Optional[float] = 5.0,
    raise_on_error: bool = True,
    **kwargs
) -> str:
    """
    Simple wrapper that returns stdout or raises exception on error.
    
    Args:
        command: Command to execute
        timeout: Timeout in seconds
        raise_on_error: Whether to raise exception on command failure
        **kwargs: Additional arguments for run_command
        
    Returns:
        Command stdout as string
        
    Raises:
        CommandTimeoutError: If command times out
        CommandExecutionError: If command fails and raise_on_error is True
    """
    result = await run_command(command, timeout=timeout, **kwargs)
    
    if result.timed_out:
        raise CommandTimeoutError(str(command), timeout)
    
    if not result.success and raise_on_error:
        raise CommandExecutionError(str(command), result)
    
    return result.stdout


async def send_snmp_trap(
    host: str,
    community: str = 'public',
    timeout: float = 5.0,
    trap_oid: str = '1.3.6.1.6.3.1.1.4.1.0',
    varbinds: Optional[list] = None,
    version: str = '2c',
    port: int = 162,
    uptime: str = '12345'
) -> CommandResult:
    """
    Send SNMP trap to specified host.
    
    Args:
        host: Target host to send trap to
        community: SNMP community string  
        timeout: Command timeout in seconds
        trap_oid: Trap OID (enterprise OID for v1, notification OID for v2c/v3)
        varbinds: List of variable bindings as strings (e.g., ['1.3.6.1.2.1.1.1.0 s "Test"'])
        version: SNMP version ('1', '2c', or '3')
        port: Target port (default 162)
        
    Returns:
        CommandResult object with execution results
        
    Examples:
        # Simple trap
        result = await send_snmp_trap('192.168.1.100', 'public')
        
        # Trap with custom data
        varbinds = [
            '1.3.6.1.2.1.1.1.0 s "System Alert"',
            '1.3.6.1.2.1.1.3.0 t 12345'
        ]
        result = await send_snmp_trap('192.168.1.100', varbinds=varbinds)
    """
    uptime = str(int(float(os.popen('cat /proc/uptime').read().split()[0]))*100)
    
    # Build base command
    if version == '1':
        # SNMPv1 trap format
        cmd_parts = [
            'snmptrap',
            f'-v{version}',
            f'-c {community}',
            f'{host}:{port}',
            trap_oid,
            'localhost',  # agent address
            '6',          # generic trap type (enterprise specific)
            '1',          # specific trap type
            uptime        # uptime
        ]
    else:
        # SNMPv2c/v3 trap format
        cmd_parts = [
            'snmptrap',
            f'-v{version}',
            f'-c {community}',
            f'{host}:{port}',
            uptime,       # uptime
            trap_oid      # notification OID
        ]
    
    # Add variable bindings if provided
    if varbinds:
        cmd_parts.extend(varbinds)
    else:
        # Add default system description if no varbinds provided
        cmd_parts.append('1.3.6.1.2.1.1.1.0 s "SNMP trap test message"')
    
    # Join command parts
    cmd = ' '.join(cmd_parts)
    print([cmd])
    return await run_command(cmd, timeout=timeout)


async def send_simple_trap(
    host: str,
    message: str,
    community: str = 'public',
    port: int = 162,
    timeout: float = 5.0
) -> bool:
    """
    Send a simple SNMP trap with a text message.
    
    Args:
        host: Target host
        message: Message to send in trap
        community: SNMP community
        port: Target port (default 162 for traps)
        timeout: Command timeout
        
    Returns:
        True if trap was sent successfully, False otherwise
    """
    varbinds = [f'1.3.6.1.2.1.1.1.0 s "{message}"']
    
    try:
        result = await send_snmp_trap(
            host=host,
            community=community,
            port=port,
            timeout=timeout,
            varbinds=varbinds
        )
        return result.success
    except Exception:
        return False


# Convenience functions for common use cases
async def run_snmp_command(snmp_cmd: str, timeout: float = 10.0) -> CommandResult:
    """Run SNMP command with appropriate timeout"""
    return await run_command(snmp_cmd, timeout=timeout)

async def get_interface_table(host: str = 'localhost', community: str = 'public') -> str:
    """Get SNMP interface table without header"""
    cmd = f'snmptable -v2c -c {community} -Cf "|" -Cw 300 {host} IF-MIB::ifTable | tail -n +2'
    return await exec_command(cmd, timeout=15.0)

async def send_snmp_trap_dmcc_unregistered(
    host: str = 'localhost',
    message: str = 'DMCC stations unregistered',
    community: str = 'public'
) -> str:
    try:
        simple_result = await send_simple_trap(host, message, community)
        print(f"Simple trap result: {simple_result}")
    except Exception as e:
        print(f"Trap error: {e}")

async def main():
    """Example usage of the async shell wrapper"""
    result  = await get_interface_table()
    print(result)
    result = await send_snmp_trap_dmcc_unregistered()
    
if __name__ == "__main__":
    # Run the main function in an event loop
    asyncio_run(main())
