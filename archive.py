import os
import shutil
import tempfile

# --------------------------
# Archive creation/extraction
# --------------------------
def make_tar_bytes(folder_path: str) -> bytes:
    """Create tar.gz archive of folder and return as bytes"""
    if not os.path.isdir(folder_path):
        raise ValueError(f"Not a directory: {folder_path}")
    
    with tempfile.NamedTemporaryFile(delete=False, suffix='.tar') as tmp:
        tmp_base = tmp.name
    
    try:
        # Create tar.gz archive
        archive_path = shutil.make_archive(tmp_base, 'gztar', root_dir=folder_path)
        
        with open(archive_path, "rb") as f:
            data = f.read()
        
        return data
    finally:
        # Cleanup temporary files
        for ext in ['', '.tar.gz']:
            try:
                os.unlink(tmp_base + ext)
            except FileNotFoundError:
                pass

def extract_tar_bytes_to(archive_bytes: bytes, out_folder: str) -> None:
    """Extract tar.gz archive bytes to output folder"""
    with tempfile.NamedTemporaryFile(delete=False, suffix='.tar.gz') as tmp:
        tmp.write(archive_bytes)
        tmp_path = tmp.name
    
    try:
        if os.path.exists(out_folder):
            shutil.rmtree(out_folder)
        os.makedirs(out_folder, exist_ok=True)
        
        shutil.unpack_archive(tmp_path, extract_dir=out_folder)
    finally:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
