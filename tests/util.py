from subprocess import run, DEVNULL, CalledProcessError
import shutil
import pytest

def git_configured() -> bool:
    if not shutil.which("git"):
        return False

    try:
        for config in [ 'user.name', 'user.email' ]:
            run(['git', 'config', config], stdout=DEVNULL, stderr=DEVNULL, check=True)
    except CalledProcessError:
        # TODO communicate this to the user running the tests
        return False

    return True

requires_git = pytest.mark.skipif(not git_configured(), reason="git is not installed or configured")

