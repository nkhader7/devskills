"""Load skill definitions from YAML files."""
import os
from pathlib import Path
from typing import Dict, List

import yaml

from .models import Skill

SKILLS_DIR = Path(__file__).parent.parent / "skills"


def load_skill_file(path: str) -> List[Skill]:
    """Load all skills from a single YAML file."""
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not data:
        return []
    if isinstance(data, list):
        return [Skill.from_dict(item) for item in data]
    return [Skill.from_dict(data)]


def load_skills_from_dir(directory: str) -> List[Skill]:
    """Load all skills from a directory of YAML files."""
    skills: List[Skill] = []
    for root, _, files in os.walk(directory):
        for fname in sorted(files):
            if fname.endswith((".yaml", ".yml")):
                fpath = os.path.join(root, fname)
                skills.extend(load_skill_file(fpath))
    return skills


def load_all_skills() -> List[Skill]:
    """Load all skills from the default skills directory."""
    return load_skills_from_dir(str(SKILLS_DIR))


def get_skills_by_id(skills: List[Skill]) -> Dict[str, Skill]:
    """Return a dict of skill_id -> Skill."""
    return {s.id: s for s in skills}


def get_skills_by_category(skills: List[Skill]) -> Dict[str, List[Skill]]:
    """Return a dict of category -> list of Skills."""
    result: Dict[str, List[Skill]] = {}
    for s in skills:
        result.setdefault(s.category, []).append(s)
    return result
