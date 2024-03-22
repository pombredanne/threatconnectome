from uuid import UUID

from sqlalchemy.orm import Session

from app import models


def get_account_by_firebase_uid(db: Session, uid: str) -> models.Account | None:
    return db.query(models.Account).filter(models.Account.uid == uid).one_or_none()


def get_account_by_id(db: Session, user_id: UUID) -> models.Account | None:
    return db.query(models.Account).filter(models.Account.user_id == str(user_id)).one_or_none()


def get_account_by_email(db: Session, email: str) -> models.Account | None:
    return db.query(models.Account).filter(models.Account.email == email).first()


def create_account(db: Session, account: models.Account) -> models.Account:
    db.add(account)
    db.flush()
    db.refresh(account)
    return account


def delete_account(db: Session, account: models.Account) -> None:
    db.delete(account)
    db.flush()


def get_action(db: Session, action_id: UUID | str) -> models.TopicAction | None:
    return (
        db.query(models.TopicAction)
        .filter(models.TopicAction.action_id == str(action_id))
        .one_or_none()
    )


def create_action(db: Session, action: models.TopicAction) -> models.TopicAction:
    db.add(action)
    db.flush()
    db.refresh(action)
    return action


def delete_action(db: Session, action: models.TopicAction) -> None:
    db.delete(action)
    db.flush()
