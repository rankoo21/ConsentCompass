import json, sys, pytest
sys.path.insert(0, str(__import__('pathlib').Path(__file__).parent))
from consent_harness import load
@pytest.fixture
def e(): return load('consent_compass.py','ConsentCompass','requests')
def test_final_classification(e):
 _,c,q,b,U=e
 c.create_request('req-1','https://policy.example/p','https://notice.example/n','https://regulator.example/r','Analyze whether analytics may use email addresses for fraud prevention.','email address and login metadata')
 b.extend(['policy','notice','regulator']*2)
 q.extend([json.dumps({'status':'RESTRICTED','basis':'requires notice','conditions':['opt out'],'confidence':84})]*2)
 c.evaluate('req-1'); r=json.loads(c.get_request('0xowner','REQ-1'))
 assert r['state']=='FINAL' and r['status']=='RESTRICTED' and len(r['digests'])==3

def test_forged_validator_and_sources(e):
 _,c,q,b,U=e
 with pytest.raises(U): c.create_request('REQ-2','https://same.example/a','https://same.example/b','https://third.example/c','A valid purpose for data use.','email')
 c.create_request('REQ-2','https://a.example/a','https://b.example/b','https://c.example/c','A valid purpose for data use.','email')
 b.extend(['policy','notice','regulator','policy','notice','regulator'])
 q.extend([json.dumps({'status':'ALLOWED','basis':'ok','conditions':[],'confidence':90}),json.dumps({'status':'BLOCKED','basis':'forged','conditions':[],'confidence':90})])
 with pytest.raises(U): c.evaluate('REQ-2')



