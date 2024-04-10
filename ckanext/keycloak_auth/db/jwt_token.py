# encoding: utf-8
from __future__ import annotations

from sqlalchemy import types, Column, ForeignKey
from sqlalchemy.orm import relationship


from sqlalchemy import Column, types
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class UserSession(Base):
    __tablename__ = "user_session"

    id = Column(types.Integer, primary_key=True)
    session_id = Column(types.String(256), unique=True, nullable=False)
    user_id = Column(types.String(256), nullable=True)
    jwttokens = relationship("JWTToken", back_populates="user_session", uselist=False)


class JWTToken(Base):
    __tablename__ = "jwttokens"

    id = Column(types.Integer, primary_key=True)
    access_token = Column(types.Text, nullable=False)
    refresh_token = Column(types.Text, nullable=False)
    user_session_id = Column(types.Integer, ForeignKey("user_session.id"))
    user_session = relationship("UserSession", back_populates="jwttokens")
