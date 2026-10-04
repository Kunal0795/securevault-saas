from celery import shared_task


@shared_task(name='audit.ping')
def ping():
    return 'pong'
