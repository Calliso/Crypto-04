from Crypto import app, templates
from fastapi import Request, Form, HTTPException
from Crypto.utils.symmetric import Symmetric
from Crypto.utils.asymmetric import Asymmetric

sym = Symmetric()
asym = Asymmetric()

"""
app endpoints
"""


def check_key():
    if(sym.key != ''):
        sym_key = sym.key.hex()
    else:
        sym_key = ''
    return sym_key


@app.get('/')
def home(request: Request):
    if 'public' in asym.keys.keys():
        public = asym.keys['public']
        private = asym.keys['private']
    else:
        public = ''
        private = ''
    return templates.TemplateResponse("index.html", {"request": request, 'sym_key': check_key(), 'public': public, 'private': private})


@app.get('/symmetric/key')
def random_key(request: Request):
    key = sym.create_key()
    return templates.TemplateResponse('random_key.html', context={'request': request, 'key': key, 'sym_key': check_key(), 'mode': 'sym'})


@app.post('/symmetric/key/set')
def set_key(request: Request, key: str = Form(...)):
    if not sym.set_key(key):
        raise HTTPException(status_code=422, detail='check data')
    return templates.TemplateResponse('set_key.html', context={'request': request, 'key': sym.key, 'sym_key': check_key()})


@app.get('/symmetric/key/set')
def set_key(request: Request):

    return templates.TemplateResponse('set_key.html', context={'request': request, 'sym_key': check_key()})


@app.post('/symmetric/encode')
def encode_message_post(request: Request, message: str = Form(...)):
    encrypted_message = sym.encode_message(message)
    if encrypted_message == message:
        raise HTTPException(status_code=422, detail='check data')
    return templates.TemplateResponse('sym_message.html', context={'message': encrypted_message, 'request': request, 'sym_key': check_key(), 'templ': 'encode'})


@app.get('/symmetric/encode')
def encode_message(request: Request):
    return templates.TemplateResponse('form.html', context={'request': request, 'path': '/symmetric/encode', 'sym_key': check_key()})


@app.post('/symmetric/decode')
def decode_message(request: Request, message: str = Form(...)):
    decrypted_message = sym.decode_message(message)
    if decrypted_message == message:
        raise HTTPException(status_code=422, detail='check data')

    return templates.TemplateResponse('sym_message.html', context={'message': decrypted_message, 'request': request, 'sym_key': check_key(), 'templ': 'decode'})


@app.get('/symmetric/decode')
def decode_message(request: Request):
    return templates.TemplateResponse('form.html', context={'request': request, 'path': '/symmetric/decode/', 'sym_key': check_key()})


@app.get('/asymmetric/keys')
def get_pem_keys(request: Request):
    temp = asym.create_pem_keys()
    return templates.TemplateResponse('random_key.html', context={'request': request, 'private': temp['private'], 'public': temp['public'], 'mode': 'asym'})


@app.get('/asymmetric/keys/ssh')
def get_ssh_keys(request: Request):
    temp = asym.create_ssh_keys()
    return templates.TemplateResponse('random_key.html', context={'request': request, 'private': temp['private'], 'public': temp['public'], 'mode': 'asym'})


@app.post('/asymmetric/keys/set')
def set_keys(public_key: str = Form(...), private_key: str = Form(...)):
    if not asym.set_keys(public_key, private_key):
        raise HTTPException(status_code=422, detail='check data')

    return {"current public key": public_key, "Current private key": private_key}


@app.get('/asymmetric/keys/set')
def set_keys(request: Request):
    return templates.TemplateResponse('asym_form.html', context={'request': request})


@app.post('/asymmetric/sign')
def sign_message(request: Request, message: str = Form(...)):
    signature = asym.sign_message(message)
    if message == signature:
        raise HTTPException(status_code=422, detail='check data')

    return templates.TemplateResponse('sign.html', context={'request': request, 'sign': signature, 'mode': 'sign'})


@app.get('/asymmetric/sign')
def sign_message(request: Request):
    return templates.TemplateResponse('form.html', context={'request': request, 'path': '/asymmetric/sign'})


@app.post('/asymmetric/verify')
def verify_message(request: Request, message: str = Form(...), signature: str = Form(...)):
    if not asym.verify_message(message, signature):
        raise HTTPException(status_code=422, detail='check data')
    return templates.TemplateResponse('sign.html', context={'request': request, 'signature': 'verified', 'sign': signature, 'mode': 'verify'})


@app.get('/asymmetric/verify')
def verify_message(request: Request):
    return templates.TemplateResponse('form_verify.html', context={'request': request})


@app.post('/asymmetric/encode')
def asym_encode_message(request: Request, message: str = Form(...)):
    encrypted_message = asym.encode_message(message)

    if message == encrypted_message:
        raise HTTPException(status_code=422, detail='Incorrect data provided')

    return templates.TemplateResponse('sym_message.html', context={'message': encrypted_message, 'request': request, 'templ': 'encode'})


@app.get('/asymmetric/encode')
def asym_encode_message(request: Request):
    return templates.TemplateResponse('form.html', context={'request': request, 'path': '/asymmetric/encode'})


@app.post('/asymmetric/decode')
def asym_decode_message(request: Request, message: str = Form(...)):
    decrypted_message = asym.decode_message(message)

    if message == decrypted_message:
        raise HTTPException(status_code=422, detail='Incorrect data provided')

    return templates.TemplateResponse('sym_message.html', context={'message': decrypted_message, 'request': request, 'templ': 'decode'})


@app.get('/asymmetric/decode')
def asym_decode_message(request: Request):
    return templates.TemplateResponse('form.html', context={'request': request, 'path': '/asymmetric/decode'})
