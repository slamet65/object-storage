package storage

import (
	bolt "go.etcd.io/bbolt"
)

// Penyimpanan kunci-nilai kecil untuk data sistem (misalnya token), di
// database metadata yang sama dengan bucket dan object. Tiap namespace
// adalah satu bucket bbolt berawalan "sys:".

func sysBucket(ns string) []byte { return []byte("sys:" + ns) }

// SysGet mengembalikan nilai untuk key, atau nil kalau tidak ada.
func (s *Store) SysGet(ns, key string) ([]byte, error) {
	var out []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket(sysBucket(ns)); b != nil {
			if v := b.Get([]byte(key)); v != nil {
				out = append([]byte(nil), v...)
			}
		}
		return nil
	})
	return out, err
}

// SysUpdate mengubah nilai untuk key secara atomik. fn menerima nilai lama
// (nil kalau belum ada); nilai baru nil berarti hapus. Error dari fn
// membatalkan perubahan.
func (s *Store) SysUpdate(ns, key string, fn func(old []byte) ([]byte, error)) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(sysBucket(ns))
		if err != nil {
			return err
		}
		v, err := fn(b.Get([]byte(key)))
		if err != nil {
			return err
		}
		if v == nil {
			return b.Delete([]byte(key))
		}
		return b.Put([]byte(key), v)
	})
}

// SysList memanggil fn untuk setiap entri namespace, terurut menurut key.
func (s *Store) SysList(ns string, fn func(key string, value []byte) error) error {
	return s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(sysBucket(ns))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error { return fn(string(k), v) })
	})
}
