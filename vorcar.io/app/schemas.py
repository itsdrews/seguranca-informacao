from pydantic import BaseModel


class PublicKeyPayload(BaseModel):
  public_key: str


class SendMessagePayload(BaseModel):
  sender_id: str
  recipient_id: str
  encrypted_content: str  # Mensagem criptografada no cliente (base64/hex)