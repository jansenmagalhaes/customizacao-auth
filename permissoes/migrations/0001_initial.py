# Generated by Django 4.2 on 2023-04-07 20:58

from django.db import migrations, models
import django.db.models.deletion
import permissoes.models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('contenttypes', '0002_remove_content_type_name'),
    ]

    operations = [
        migrations.CreateModel(
            name='Permissao',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
                ('codename', models.CharField(max_length=100)),
                ('content_type', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='contenttypes.contenttype', verbose_name='content type')),
            ],
            options={
                'verbose_name': 'permissão',
                'verbose_name_plural': 'permissões',
                'db_table': 'permissoes',
                'ordering': ['content_type__app_label', 'content_type__model', 'codename'],
                'managed': True,
                'unique_together': {('content_type', 'codename')},
            },
            managers=[
                ('objects', permissoes.models.PermissaoManager()),
            ],
        ),
    ]