from sqlalchemy.orm import Session

from app import models


def get_account_by_uid(db: Session, uid: str) -> models.Account | None:
    return db.query(models.Account).filter(models.Account.uid == uid).one_or_none()


def create_account(db: Session, account: models.Account) -> models.Account:
    db.add(account)
    db.flush()
    db.refresh(account)
    return account


def delete_account(db: Session, account: models.Account) -> None:
    db.delete(account)
    db.flush()
