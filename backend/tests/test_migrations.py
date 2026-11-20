"""The migration chain must stay a single line: two migrations with the same parent (easy after merging branches) make
`alembic upgrade head` fail on every server with "Multiple head revisions are present"."""
import os

from alembic.config import Config
from alembic.script import ScriptDirectory

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_single_migration_head():
    config = Config(os.path.join(ROOT, "alembic.ini"))
    config.set_main_option("script_location", os.path.join(ROOT, "migrations"))
    script = ScriptDirectory.from_config(config)
    heads = script.get_heads()
    assert len(heads) == 1, f"More than one migration head: {sorted(heads)}. Make the newest migration's down_revision point at the other head."
    parents: dict[str, list[str]] = {}
    for rev in script.walk_revisions():
        for parent in ([rev.down_revision] if isinstance(rev.down_revision, str) else rev.down_revision or []):
            parents.setdefault(parent, []).append(rev.revision)
    forks = {p: kids for p, kids in parents.items() if len(kids) > 1}
    assert not forks, f"Migrations sharing a parent: {forks}"
