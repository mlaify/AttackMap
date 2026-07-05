import subprocess


def kickoff(payload):
    target = payload["target"]
    return subprocess.run(f"deploy.sh {target}", shell=True)
