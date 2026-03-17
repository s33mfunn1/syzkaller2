# 2) Создать corpus.db
./bin/syz-db -os=linux -arch=amd64 pack ./corpus_seeds/ workdir/corpus.db
# 3) Проверить
./bin/syz-db print workdir/corpus.db