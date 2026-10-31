"""Deprecated shim: the package was renamed to mcp_gradecard."""
import warnings

from mcp_gradecard import *  # noqa: F401,F403
from mcp_gradecard import __version__  # noqa: F401

warnings.warn(
    "mcp_audit is renamed mcp_gradecard; import mcp_gradecard instead",
    DeprecationWarning, stacklevel=2)
