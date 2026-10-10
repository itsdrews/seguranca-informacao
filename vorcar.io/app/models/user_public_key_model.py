from database import Base
from sqlalchemy import Column, LargeBinary, String


class UserPublicKeyModel(Base):
  __tablename__ = "public_keys"

  user_id = Column(String, primary_key=True, index=True)
  public_key = Column(LargeBinary, nullable=False)