from django.db import models

class Estado(models.Model):
    nome = models.CharField(max_length=50)

    class Meta:
        db_table = 'estados'
        managed = True
        verbose_name = 'Estado'
        verbose_name_plural = 'Estados'