import datetime
import decimal
from enum import Enum
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, EmailStr


class Credentials(BaseModel):

    Login: str
    Password: str


class BearerData(BaseModel):

    token: str
    secret: str


class RequestState(int, Enum):

    Success = 0
    WithWarn = 1
    NoAuth = 2


class OperationState(BaseModel):

    Code: RequestState
    Desc: str


class UserToken(str):
    pass


class UserTokenData(BaseModel):

    State: OperationState
    UserToken: UserToken


class InvoiceState(str, Enum):

    Created = 'Created'
    PartPaid = 'PartPaid'
    Paid = 'Paid'
    ToPaid = 'ToPaid'
    Refund = 'Refund'
    Held = 'Held'


class IsHoldingSearch(int, Enum):

    WithoutOrganizations = 0
    WithOrganizations = 1


class InvoiceSortOrder(str, Enum):

    CreationDate = 1
    ChangeDate = 2
    InvoiceState = 3
    Amount = 4


class GetInvoicesHistory(BaseModel):

    UserToken: UserToken
    EshopId: Optional[int]
    OrganizationId: Optional[int]
    State: Optional[InvoiceState]
    InvoiceId: Optional[int]
    IncludePaymentTransactions: Optional[bool]
    IsHoldingSearch: Optional[IsHoldingSearch]
    OwnerEmail: Optional[EmailStr]
    SortOrder: Optional[InvoiceSortOrder]
    DateFrom: Optional[datetime.date]
    DateTo: Optional[datetime.date]
    ChangeDateFrom: Optional[datetime.date]
    ChangeDateTo: Optional[datetime.date]
    Skip: Optional[int]
    Take: int


class OperationCode(int, Enum):

    Success = 0
    Process = 1
    Error = 2


class OperationState(BaseModel):

    Code: OperationCode
    Desc: str


class BaseResponse(BaseModel):

    OperationState: OperationState
    OperationId: Optional[UUID]
    EshopId: Optional[int]
    Result: Optional[dict]


class Currency(str, Enum):

    RUB = 'RUB'
    TST = 'TST'


class Money(BaseModel):

    Amount: decimal.Decimal
    Currency: Currency


class TransactionState(str, Enum):

    Created = 'Created'
    Confirm = 'Confirm'
    Canceled = 'Canceled'


class PaymentType(str, Enum):

    Entry = 'Entry'
    Purchase = 'Purchase'
    Refund = 'Refund'


class HistoryData(BaseModel):

    Id: int
    PaymentNumber: int
    State: TransactionState
    CreationDate: datetime.datetime
    PaymentAmount: Money
    RecipientAmount: Money
    PaymentAccount: str
    RecipientAccount: str
    Description: str
    InvoicePaymentType: PaymentType


class InvoiceData(BaseModel):

    Id: int
    State: InvoiceState
    CreationDate: datetime.datetime
    ChangeDate: datetime.datetime
    Amount: Money
    CurrentAmount: Money
    SurchargeAmount: Money
    Comment: str
    EShopId: int
    PurchaseOrderId: str
    HistoryList: Optional[List[HistoryData]]


class InvoicesHistoryList(BaseModel):

    State: OperationState
    InvoicesHistoryList: List[InvoiceData]


class InvoicesResponse(BaseResponse):

    Result: InvoicesHistoryList


class GetPaymentsHistory(BaseModel):

    UserToken: UserToken
    EshopId: Optional[int]
    PaymentTransactionId: Optional[int]
    DateFrom: Optional[datetime.date]
    DateTo: Optional[datetime.date]
    Skip: Optional[int]
    Take: int


class PaymentsHistoryList(BaseModel):

    State: OperationState
    InvoicesHistoryList: List[InvoiceData]


class PaymentsResponse(BaseResponse):

    Result: PaymentsHistoryList
