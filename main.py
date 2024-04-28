import os
import json
import concurrent.futures
from pandas import DataFrame as df
import processing.extractor as extractor

# main function to start the extraction process

def main() -> df:
    _extractor = extractor.Extractor()
    cves = _extractor.transform(["alpine","nvd","mitre"])
    return cves
if __name__ == "__main__":
    main()