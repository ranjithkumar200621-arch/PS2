import unittest
import httpx
from unittest.mock import patch
from evidence import domain_evidence, bounded_json

class EvidenceTests(unittest.IsolatedAsyncioTestCase):
    async def test_only_registry_is_visited(self):
        visited=[]
        def respond(request):
            visited.append(str(request.url))
            return httpx.Response(200,json={'events':[{'eventAction':'registration','eventDate':'2020-01-01T00:00:00Z'}]})
        with patch('evidence.BOOTSTRAP',{'services':[[['com'],['https://registry.example/']]]}):
            async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
                result=await domain_evidence(client,'https://scam.example.com/private')
        self.assertEqual(visited,['https://registry.example/domain/example.com'])
        self.assertEqual(result['status'],'available');self.assertNotIn('verdict',result)
    async def test_failure_does_not_imply_safety(self):
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r:httpx.Response(503))) as client:
            result=await domain_evidence(client,'https://example.com')
        self.assertEqual(result['status'],'unavailable')
    async def test_redirect_not_followed(self):
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r:httpx.Response(302,headers={'location':'http://127.0.0.1/secrets'})),follow_redirects=False) as client:
            with self.assertRaises((httpx.HTTPError,ValueError)):await bounded_json(client,'https://registry.example/')
    async def test_oversized_response_rejected(self):
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r:httpx.Response(200,content=b' '*300000))) as client:
            with self.assertRaises(ValueError):await bounded_json(client,'https://registry.example/')
