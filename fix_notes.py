import os
import glob


def fix_file(filepath):
    with open(filepath, "r") as f:
        lines = f.readlines()

    new_lines = []
    for line in lines:
        if "# 0" in line and "tags=[" in line:
            # It was a note line that got mangled
            pass  # just remove it
        elif ".note(" in line:
            new_lines.append("# " + line)
        else:
            new_lines.append(line)

    with open(filepath, "w") as f:
        f.writelines(new_lines)


for root, dirs, files in os.walk("src/cloudsecurity_af"):
    for file in files:
        if file.endswith(".py"):
            fix_file(os.path.join(root, file))
