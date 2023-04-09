# Generated by Django 4.2 on 2023-04-07 20:58

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('perfis', '0001_initial'),
        ('permissoes', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='perfil',
            name='permissao',
            field=models.ManyToManyField(blank=True, db_table='perfis_permissoes', to='permissoes.permissao', verbose_name='permissions'),
        ),
    ]