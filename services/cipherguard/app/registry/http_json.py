"""Bound registry downloads before JSON decoding; no redirects to artifact URLs."""
import asyncio
import json
import httpx

async def fetch(client,url,semaphore,logger,max_bytes=8*1024*1024):
    for attempt in range(2):
        try:
            async with semaphore:
                async with client.stream('GET',url,timeout=2,follow_redirects=False) as response:
                    if response.status_code==404:return 404,{}
                    if response.status_code!=200:
                        response.raise_for_status()
                        raise ValueError('Registry redirect refused')
                    length=response.headers.get('content-length')
                    if length and int(length)>max_bytes:raise ValueError('Registry data exceeds response budget')
                    body=bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body)>max_bytes:raise ValueError('Registry data exceeds response budget')
                    data=json.loads(body)
                    if not isinstance(data,dict):raise ValueError('Registry metadata must be an object')
                    return 200,data
        except (httpx.HTTPError,ValueError,UnicodeError) as error:
            if attempt==1:
                logger.warning('Registry metadata verification failed (%s)',type(error).__name__)
                return 500,{}
            await asyncio.sleep(.1)
    return 500,{}
