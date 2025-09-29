# SourcePatcher

## Description
Super simple patching script to allow building and applying patches to any source code.

## Usage
### Setup
Very simple: 
- Download `loader.py`
- `loader.py` will keep your `source_patcher.py` up to date automatically (includes signed header to ensure security)
- Put your source in folder named "project"

### Create Patches
- Run `loader.py exec rebuild`
- First commit will be ignored (this can be used to avoid uploading sources to your repo due to copyright)
- You will now have a folder named "patches"

### Editing the Base
You will likely want to edit your decompiled source at some point.  
  
To do this this, it's very simple: `loader.py exec reset`  
WARNING: This will delete any commits that were not turned into patches!  

You can now edit your first commit (likely decompiled source) and apply changes using `git commit --amend ...`

### Applying Patches
- Run `loader.py exec patch`
- The script will attempt to apply each patch 1 by 1 onto the new base (decompiled binary)

## Recommendations
It is recommended to pair this script with an initializing script which can create a base project and decompile a binary for the user. This is not provided in this project. 
