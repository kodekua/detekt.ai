import json
import os
import pandas as pd
import concurrent.futures as ft


# Extractor class   
class Extractor:
    def __init__(self) -> None:
        pass

    @classmethod
    def _extract(self, source:str) -> list:
        extracted_data=[]
        dir_path="data/"+source+"/"
        if source in ["alpine", "nvd", "mitre"]:
            for file in os.scandir(dir_path):
                if file.name.endswith(".json"):
                    filepath=os.path.join(dir_path,file.name)
                    with open(filepath, "r") as f:
                        dict_items = json.load(f)
                    f.close()
                if source == "alpine":
                    extracted_data += dict_items['packages']
                elif source == "nvd":
                    extracted_data += dict_items['CVE_Items']
                elif source == "mitre":
                    extracted_data += dict_items
                else:
                    print("Unknown source! Valid sources are: alpine, nvd, mitre")
                    os._exit(-1)
            return extracted_data
        else:
            print("Unknown source! Valid sources are: alpine, nvd, mitre")
            os._exit(-1)

    @classmethod
    def _parse_data(self, source:str) -> pd.DataFrame:
        data=self._extract(source)
        output=[]
        df_columns=["package", "version", "vendor","id","severity", "status"]

        if source == "alpine":
            for package in data:
                for version in package["pkg"]["secfixes"].keys():
                    for cve_item in package["pkg"]["secfixes"][version]:
                        _cve={"package": package["pkg"]["name"], "version": version, "vendor": "n/a", "id": cve_item, "severity": "n/a", "status": "n/a"}
                        output.append(_cve)
            return pd.DataFrame(output, columns=df_columns)
        elif source == "nvd":
            for package in data:
                _cve={"package": "n/a", "version": "n/a", "vendor": "n/a", "id": package["cve"]["CVE_data_meta"]["ID"], "severity": "n/a", "status": "n/a"}
                if 'baseMetricV3' in package['impact']:
                    _cve["severity"] = package['impact']['baseMetricV3']['cvssV3']['baseSeverity']
                output.append(_cve)
            return pd.DataFrame(output, columns=df_columns)
        elif source == "mitre":    
            for package in data:
                _cve={"package": package['containers']['cna'].get('affected', [{'product': 'n/a'}])[0].get('product', 'n/a'),
                       "version": package['containers']['cna'].get('affected', [{'vendor': 'n/a'}])[0].get('versions', [{'version': 'n/a'}])[0].get('version', 'n/a'),
                       "vendor": package['containers']['cna'].get('affected', [{'vendor': 'n/a'}])[0].get('vendor', 'n/a'),
                       "id": package['cveMetadata']['cveId'],
                       "severity": "n/a",
                       "status": package['containers']['cna'].get('affected', [{'vendor': 'n/a'}])[0].get('versions', [{'status': 'n/a'}])[0].get('status', 'n/a')}
                if 'metrics' in package['containers']['cna']:
                    if 'cvssV3_1' in package['containers']['cna']['metrics'][0]:
                        _cve["severity"] = package['containers']['cna']['metrics'][0]['cvssV3_1']['baseSeverity']
                    elif 'cvssV3_0' in package['containers']['cna']['metrics'][0]:
                        _cve["severity"] = package['containers']['cna']['metrics'][0]['cvssV3_0']['baseSeverity']
                    else:
                        _cve["severity"] = "Unknown"
                else:
                    _cve["severity"] = "Unknown"
                output.append(_cve)
            return pd.DataFrame(output, columns=df_columns)
        else:
            os.exit(-1)


    def transform(self, sources:list[str]) -> dict[str:pd.DataFrame]:
        list_of_df=[]

        with ft.ThreadPoolExecutor(max_workers=100) as executor:
            future_to_data = {executor.submit(self._parse_data, source): source for source in sources}
            for future in ft.as_completed(future_to_data):
                source = future_to_data[future]
                try:
                    data = future.result()
                    list_of_df.append(data)
                except Exception as exc:
                    print(f"Failed to fetch data from {source}. Exception: {exc}")
        
        concat_df = pd.concat(list_of_df)
        concat_df.to_csv('data/full_cve_data.csv', index=False)
        merged_df = concat_df.groupby('id').agg({"package": ", ".join, "version": ", ".join, "vendor": ", ".join, "severity": ", ".join, "status": ", ".join}).reset_index()
        merged_df.to_csv('data/merged_cve_data.csv', index=False)

        return {"concated": concat_df, "merged": merged_df}