import requests
from typing import Optional
import hashlib

from im.models import (
    BaseResponse, BearerData, Credentials, GetInvoicesHistory, GetPaymentsHistory, InvoicesHistoryList,
    InvoicesResponse, OperationCode, PaymentsHistoryList, PaymentsResponse, UserToken,
    UserTokenData)


class ApiException(Exception):
    pass


def _get_result(part_of_url: str, data: dict, bearer_data: Optional[BearerData] = None, timeout: int = 30) -> dict:
    headers = {'Accept': 'text/json'}

    if bearer_data:
        login = data['Login']
        password = data['Password']
        encoded_secret = f"::{login}::{password}::::{bearer_data.secret}".encode('utf-8')
        secret_key = hashlib.sha256(encoded_secret).hexdigest()
        bearer_data = {"Authorization": f"Bearer {bearer_data.token}", "Sign": secret_key}
        headers.update(bearer_data)

    data = requests.post(f'https://api.intellectmoney.ru/personal/{part_of_url}',
                         data=data,
                         headers=headers,
                         timeout=timeout).json()
    resp = BaseResponse(**data)
    if resp.OperationState.Code != OperationCode.Success:
        raise ApiException(data)
    return resp.Result


def getUserToken(credentials: Credentials, bearer: Optional[BearerData] = None) -> UserToken:
    data = _get_result('user/getUserToken', credentials.dict(), bearer)
    return UserTokenData(**data).UserToken


def getPaymentsHistory(reqData: GetPaymentsHistory) -> PaymentsHistoryList:
    return PaymentsHistoryList(**_get_result('payment/getPaymentsHistory', reqData.dict()))


def getInvoicesHistory(reqData: GetInvoicesHistory) -> InvoicesHistoryList:
    return InvoicesHistoryList(**_get_result('payment/getInvoicesHistory', reqData.dict()))
