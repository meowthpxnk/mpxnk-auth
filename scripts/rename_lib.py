import os
import sys
import re
from pathlib import Path


def main():
    root_dir = Path.cwd()
    pyproject_path = root_dir / "pyproject.toml"

    if not pyproject_path.exists():
        print(
            "❌ Error: pyproject.toml file not found in the current directory."
        )
        sys.exit(1)

    # 1. Determine the new package name (from arguments or parent folder name)
    if len(sys.argv) > 1:
        # Manual mode with argument: poetry run rename_lib mpxnk-test-library
        new_name_dash = sys.argv[1].strip()
        print(
            f"ℹ️ Using name provided in command line arguments: {new_name_dash}"
        )
    else:
        # Standard mode: taking current folder name
        new_name_dash = root_dir.name.strip()
        print(
            f"ℹ️ Automatically detected name from folder title: {new_name_dash}"
        )

    # Validate name format (must match standard format like mpxnk-test-library)
    # Allows alphanumeric characters and dashes
    if not re.match(r"^[a-zA-Z0-9\-]+$", new_name_dash):
        print(
            f"⚠️ Error: The name '{new_name_dash}' does not match the required format (e.g., mpxnk-test-library)."
        )
        print(
            "\n💡 Please run the script in manual mode by specifying the target name as an argument:"
        )
        print("   poetry run rename_lib YOUR-PACKAGE-NAME")
        sys.exit(1)

    # Generate underscore version for packages/imports
    new_name_underscore = new_name_dash.replace("-", "_")

    # Target placeholders to find in pyproject.toml
    old_name_dash = "YOUR-PACKAGE-NAME"
    old_name_underscore = "YOUR_PACKAGE_NAME"

    print("🔄 Starting the renaming process...")

    # 2. Read and update pyproject.toml
    try:
        content = pyproject_path.read_text(encoding="utf-8")

        # Check if placeholders exist in the file
        if old_name_dash not in content and old_name_underscore not in content:
            print(
                "ℹ️ Warning: 'YOUR-PACKAGE-NAME' placeholders not found in pyproject.toml. Already renamed?"
            )
        else:
            updated_content = content.replace(old_name_dash, new_name_dash)
            updated_content = updated_content.replace(
                old_name_underscore, new_name_underscore
            )
            pyproject_path.write_text(updated_content, encoding="utf-8")
            print("✅ pyproject.toml successfully updated.")
    except Exception as e:
        print(f"❌ Error while processing pyproject.toml: {e}")
        sys.exit(1)

    # 3. Rename the source code directory
    old_folder = root_dir / old_name_underscore
    new_folder = root_dir / new_name_underscore

    if old_folder.exists() and old_folder.is_dir():
        try:
            old_folder.rename(new_folder)
            print(
                f"✅ Folder '{old_name_underscore}' successfully renamed to '{new_name_underscore}'."
            )
        except Exception as e:
            print(f"❌ Error while renaming source folder: {e}")
            sys.exit(1)
    elif new_folder.exists() and new_folder.is_dir():
        print(f"ℹ️ Folder '{new_name_underscore}' already exists.")
    else:
        print(
            f"⚠️ Warning: Source folder '{old_name_underscore}' not found for renaming."
        )

    print(f"\n🎉 Project successfully renamed to '{new_name_dash}'!")


if __name__ == "__main__":
    main()
