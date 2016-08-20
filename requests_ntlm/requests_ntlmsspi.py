from sspi import ClientAuth
from requests.auth import AuthBase
import base64

class HttpNtlmSspiAuth(AuthBase):
    """Requests extension to auto-authenticate user.

    HTTP NTLM Authentication using SSPI for passwordless login.
    """

    def __init__(self):
        pass

    def __call__(self, r):
        self.AuthGen = ClientAuth("NTLM")
        r.headers["Connection"] = "Keep-Alive"
        r.register_hook('response', self.response_hook)
        return r

    def response_hook(self, r, **kwargs):
        """
        Identifies the type of authentication needed and the header title
        and routes the information to perform the authentication dance
        """
        www_authenticate = r.headers.get('www-authenticate', '').lower()
        if r.status_code == 401 and 'ntlm' in www_authenticate:
            return self.apply_sspi('www-authenticate', 'Authorization', r, kwargs)

        proxy_authenticate = r.headers.get('proxy-authenticate', '').lower()
        if r.status_code == 407 and 'ntlm' in proxy_authenticate:
            return self.apply_sspi('proxy-authenticate', 'Proxy-authorization', r, kwargs)
        return r

    def authenticate(self, challenge=None):
        """Performs the authentication handshake

        Parameters
        ----------
        challenge : str, optional
            Challenge is the response encoded response from the web-server that is
            typically the response to the client's initial challenge. When `challenge`
            is called without a `challenge`, it generates the first challenge to the
            server that open the communication between them.

        Returns
        -------
        str
            Returns a challenge for the server. That will either initiate the
            communication, or respond to the webservice's challenge.
        """
        challenge = base64.b64decode(challenge) if challenge else None
        _, output_buffer = self.AuthGen.authorize(challenge)
        encode = base64.b64encode(output_buffer[0].Buffer)
        return 'NTLM %s' % encode.decode().replace('\n', '')

    def new_request(self, response):
        response.content
        response.raw.release_conn()
        return response.request.copy()

    def apply_sspi(self, auth_header_field, auth_header, response, args):
        """Performs the authentication dance between server and client.
        """
        if auth_header in response.request.headers:
            return response

        # A streaming response breaks authentication. Disabled for authentication dance
        # set back to default (args) for final return
        request = self.new_request(response)
        request.headers[auth_header] = self.authenticate()
        # In case authentication info stored in cookies
        if response.headers.get('set-cookie'):
            request.headers['Cookie'] = response.headers.get('set-cookie')
        response1 = response.connection.send(request, **dict(args, stream=False))

        # Previous request/response sent initial msg to begin dance.
        # Now we authenticate using the response
        request = self.new_request(response1)
        ntlm_header_value = response1.headers[auth_header_field][5:]
        request.headers[auth_header] = self.authenticate(ntlm_header_value)

        # In case authentication info stored in cookies
        if response1.headers.get('set-cookie'):
            request.headers['Cookie'] = response1.headers.get('set-cookie')
        
        # append session with history for cookies like <Cookie ARPT>
        responseFinal = response.connection.send(request, **args)
        responseFinal.history.append(response)
        responseFinal.history.append(response1)
        
        
        return responseFinal
