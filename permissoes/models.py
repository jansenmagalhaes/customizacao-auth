from django.db import models
from django.contrib.contenttypes.models import ContentType
from django.utils.translation import gettext_lazy as _

class PermissaoManager(models.Manager):
    use_in_migrations = True

    def get_by_natural_key(self, codename, app_label, model):
        return self.get(
            codename=codename,
            content_type=ContentType.objects.db_manager(self.db).get_by_natural_key(
                app_label, model
            ),
        )

class Permissao(models.Model):
    name = models.CharField(max_length=255)
    content_type = models.ForeignKey(
        ContentType,
        models.CASCADE,
        verbose_name=_("content type"),
    )
    codename = models.CharField(max_length=100)

    objects = PermissaoManager()

    class Meta:
        db_table = "permissoes"
        managed = True
        verbose_name = "permissão"
        verbose_name_plural = "permissões"
        unique_together = [["content_type", "codename"]]
        ordering = ["content_type__app_label", "content_type__model", "codename"]

    def __str__(self):
        return "%s | %s" % (self.content_type, self.name)

    def natural_key(self):
        return (self.codename,) + self.content_type.natural_key()

    natural_key.dependencies = ["contenttypes.contenttype"]