import hashlib, pathlib, urllib.request, time, json
REV='614241f622f53c4eeff9890bdc4f31cfecc418b3'
root=pathlib.Path('/model'); root.mkdir(exist_ok=True)
files=['config.json','model.safetensors','tokenizer.json','tokenizer_config.json','special_tokens_map.json','sentencepiece.bpe.model','modules.json','sentence_bert_config.json','1_Pooling/config.json']
expected=json.loads(pathlib.Path('/app/model-sha256.json').read_text())
manifest={}
for name in files:
    path=root/name; path.parent.mkdir(parents=True,exist_ok=True)
    for attempt in range(4):
        try:
            with urllib.request.urlopen(f'https://huggingface.co/intfloat/multilingual-e5-small/resolve/{REV}/{name}',timeout=180) as r, path.open('wb') as f:
                while chunk:=r.read(1024*1024): f.write(chunk)
            break
        except Exception:
            if attempt==3: raise
            time.sleep(2**attempt)
    manifest[name]=hashlib.sha256(path.read_bytes()).hexdigest()
    assert manifest[name]==expected[name], 'download_checksum_mismatch'
(root/'SHA256SUMS.json').write_text(json.dumps(manifest,indent=2))
(root/'REVISION').write_text(REV)
print(json.dumps(manifest,indent=2))
