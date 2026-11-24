from http.server import ThreadingHTTPServer,BaseHTTPRequestHandler
import json, threading, math, hashlib, pathlib
from sentence_transformers import SentenceTransformer
import torch
REV='614241f622f53c4eeff9890bdc4f31cfecc418b3'
root=pathlib.Path('/model')
for name,expected in json.loads((root/'SHA256SUMS.json').read_text()).items():
    assert hashlib.sha256((root/name).read_bytes()).hexdigest()==expected, 'model_checksum_failed'
torch.set_num_threads(2)
model=SentenceTransformer('/model',device='cpu',trust_remote_code=False,local_files_only=True)
model.max_seq_length=512
lock=threading.Lock()

def chunks(text):
    # Split with the real tokenizer, retaining exact decoded fragments.
    ids=model.tokenizer.encode(text,add_special_tokens=False)
    return [{'text':model.tokenizer.decode(ids[i:i+380],skip_special_tokens=True),'token_count':len(ids[i:i+380])} for i in range(0,len(ids),380)]
class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def respond(self,status,data):
        body=json.dumps(data,allow_nan=False).encode();self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    def do_GET(self):
        if self.path=='/health':self.respond(200,{'model_revision':REV,'dimension':384})
        else:self.respond(404,{'error':'not_found'})
    def do_POST(self):
        try:
            n=int(self.headers.get('Content-Length','0'))
            if not 0<n<=140000: raise ValueError('body_limit')
            data=json.loads(self.rfile.read(n))
            if self.path=='/chunks':
                if set(data)!={'text'} or not isinstance(data['text'],str) or len(data['text'].encode())>32768:raise ValueError('invalid_text')
                with lock: parts=chunks(data['text'])
                self.respond(200,{'chunks':parts,'model_revision':REV});return
            if self.path!='/embed' or set(data)!={'texts','kind'}:raise ValueError('invalid_request')
            texts=data['texts'];kind=data['kind']
            if kind not in ('query','passage') or not isinstance(texts,list) or not 1<=len(texts)<=16: raise ValueError('invalid_batch')
            if any(not isinstance(t,str) or not t.strip() or len(t.encode())>8192 for t in texts):raise ValueError('text_limit')
            with lock:
                prepared=[]
                for t in texts:
                    ids=model.tokenizer.encode(kind+': '+t,add_special_tokens=True)
                    if len(ids)>512:
                        if kind=='passage':raise ValueError('token_limit')
                        t=model.tokenizer.decode(model.tokenizer.encode(t,add_special_tokens=False)[:480],skip_special_tokens=True)
                    prepared.append(kind+': '+t)
                vectors=model.encode(prepared,normalize_embeddings=True,show_progress_bar=False).tolist()
            if any(len(v)!=384 or not all(math.isfinite(x) for x in v) for v in vectors):raise ValueError('invalid_vectors')
            self.respond(200,{'vectors':vectors,'model_revision':REV,'dimension':384})
        except (ValueError,KeyError,TypeError,json.JSONDecodeError):self.respond(400,{'error':'invalid_embedding_request'})
        except Exception:self.respond(503,{'error':'embedding_unavailable'})
ThreadingHTTPServer(('0.0.0.0',8001),Handler).serve_forever()
