from django.db import models
from estados.models import Estado

class Cidade(models.Model):
    nome = models.CharField(max_length=50)
    estado = models.ForeignKey(Estado, on_delete=models.CASCADE)

    class Meta:
        db_table = 'cidades'
        managed = True
        verbose_name = 'Cidade'
        verbose_name_plural = 'Cidades'