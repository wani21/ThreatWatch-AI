import json
import os

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    notebook_path = os.path.join(base_dir, "..", "app", "ml", "models", "ALMAS_IsolationForest.ipynb")
    output_script_path = os.path.join(base_dir, "train_model.py")

    print(f"[*] Reading Jupyter Notebook from: {notebook_path}")
    
    if not os.path.exists(notebook_path):
        print(f"[!] Error: Jupyter Notebook does not exist at {notebook_path}")
        return

    with open(notebook_path, "r", encoding="utf-8") as f:
        notebook = json.load(f)

    code_cells = []
    for cell in notebook.get("cells", []):
        if cell.get("cell_type") == "code":
            source = cell.get("source", [])
            # source can be a list of strings or a single string
            if isinstance(source, list):
                code = "".join(source)
            else:
                code = source
            code_cells.append(code)

    full_code = "\n\n# " + "="*60 + "\n# NEW CELL\n# " + "="*60 + "\n".join(code_cells)

    print(f"[*] Writing {len(code_cells)} code cells to standalone script: {output_script_path}")
    with open(output_script_path, "w", encoding="utf-8") as f:
        f.write(full_code)
    
    print("[+] Done! Standalone script generated.")

if __name__ == "__main__":
    main()
