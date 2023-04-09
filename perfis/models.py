from django.db import models
from django.utils.translation import gettext_lazy as _
from permissoes.models import Permissao

class PerfilManager(models.Manager):
    use_in_migrations = True

    def get_by_natural_key(self, name):
        return self.get(name=name)


class Perfil(models.Model):
    name = models.CharField(max_length=150, unique=True)
    permissao = models.ManyToManyField(
        Permissao,
        verbose_name=_("permissions"),
        blank=True,
        db_table="perfis_permissoes",
    )

    objects = PerfilManager()

    class Meta:
        db_table = "perfis"
        managed = True        
        verbose_name = "perfil"
        verbose_name_plural = "perfis"

    def __str__(self):
        return self.name

    def natural_key(self):
        return (self.name,)
