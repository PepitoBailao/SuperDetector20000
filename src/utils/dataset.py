import os, urllib.request, zipfile

JULIET_URL = "https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip"

def download_and_extract(url, name, base_dir="datasets"):
    path = os.path.join(base_dir, name)
    os.makedirs(path, exist_ok=True)
    z = os.path.join(path, f"{name}.zip")
    print("downloading:", name)
    urllib.request.urlretrieve(url, z)
    with zipfile.ZipFile(z) as zp:
        print("extracting:", name)
        zp.extractall(os.path.join(path, "extracted"))
    os.remove(z)
    print("done:", name)

if __name__ == "__main__":
    download_and_extract(JULIET_URL, "juliet")