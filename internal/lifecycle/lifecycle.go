// Package lifecycle menjalankan aturan lifecycle bucket di latar belakang:
// menghapus object yang kedaluwarsa, memindahkan storage class, dan
// membatalkan multipart upload yang terbengkalai.
//
// Pekerja tidak menyimpan keadaan. Setiap putaran memindai ulang semua
// bucket yang punya aturan aktif, dan setiap aksinya idempoten, jadi
// putaran yang terputus (misalnya karena restart) cukup diulang.
package lifecycle

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"object-storage/internal/storage"
)

const day = 24 * time.Hour

// pageSize adalah jumlah entri yang diperiksa per transaksi baca, supaya
// pemindaian bucket besar tidak menahan satu transaksi terlalu lama.
const pageSize = 1000

type Worker struct {
	Store  *storage.Store
	Logger *slog.Logger
	Now    func() time.Time // nil berarti time.Now
}

// Stats merangkum satu putaran.
type Stats struct {
	Expired      int // object dihapus
	Transitioned int // object dipindah storage class
	Aborted      int // multipart upload dibatalkan
	Locked       int // object kedaluwarsa yang dilewati karena bucket lock
}

func (w *Worker) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

// Run menjalankan RunOnce setiap interval sampai ctx dibatalkan.
func (w *Worker) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		stats, err := w.RunOnce(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			w.Logger.Error("putaran lifecycle gagal", "err", err)
		}
		// Putaran yang hanya melewati object terkunci tidak dicatat, supaya
		// log tidak terisi baris yang sama setiap putaran.
		if stats.Expired+stats.Transitioned+stats.Aborted > 0 {
			w.Logger.Info("putaran lifecycle selesai", "dihapus", stats.Expired, "dipindah", stats.Transitioned,
				"upload_dibatalkan", stats.Aborted, "terkunci", stats.Locked)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// due melaporkan apakah aksi berbasis umur atau tanggal sudah jatuh tempo
// untuk sesuatu yang berumur sejak since.
func due(now, since time.Time, days int, date *time.Time) bool {
	if days > 0 && !now.Before(since.Add(time.Duration(days)*day)) {
		return true
	}
	return date != nil && !now.Before(*date)
}

// RunOnce menerapkan aturan lifecycle semua bucket satu kali.
func (w *Worker) RunOnce(ctx context.Context) (Stats, error) {
	var stats Stats
	buckets, err := w.Store.ListBuckets()
	if err != nil {
		return stats, err
	}
	for _, b := range buckets {
		var objectRules, uploadRules []storage.LifecycleRule
		for _, r := range b.Lifecycle {
			if !r.Enabled {
				continue
			}
			if r.ExpireDays > 0 || r.ExpireDate != nil || r.TransitionClass != "" {
				objectRules = append(objectRules, r)
			}
			if r.AbortUploadDays > 0 {
				uploadRules = append(uploadRules, r)
			}
		}
		if len(objectRules) > 0 {
			if err := w.scanObjects(ctx, b.Name, objectRules, &stats); err != nil {
				return stats, err
			}
		}
		if len(uploadRules) > 0 {
			if err := w.scanUploads(ctx, b.Name, uploadRules, &stats); err != nil {
				return stats, err
			}
		}
	}
	return stats, nil
}

func (w *Worker) scanObjects(ctx context.Context, bucket string, rules []storage.LifecycleRule, stats *Stats) error {
	marker := ""
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		page, err := w.Store.List(bucket, "", "", marker, pageSize)
		if errors.Is(err, storage.ErrNoSuchBucket) {
			return nil // bucket dihapus selagi dipindai
		}
		if err != nil {
			return err
		}
		now := w.now()
		for _, o := range page.Objects {
			if err := w.apply(bucket, o, rules, now, stats); err != nil {
				return err
			}
		}
		if !page.IsTruncated {
			return nil
		}
		marker = page.NextMarker
	}
}

func (w *Worker) apply(bucket string, o storage.ObjectInfo, rules []storage.LifecycleRule, now time.Time, stats *Stats) error {
	expire, class := false, ""
	for _, r := range rules {
		if !strings.HasPrefix(o.Key, r.Prefix) {
			continue
		}
		if due(now, o.ModTime, r.ExpireDays, r.ExpireDate) {
			expire = true
		}
		if r.TransitionClass != "" && due(now, o.ModTime, r.TransitionDays, r.TransitionDate) {
			class = r.TransitionClass
		}
	}
	switch {
	case expire:
		// Hapus hanya kalau object belum berubah sejak dipindai.
		errChanged := errors.New("object berubah")
		err := w.Store.DeleteObjectIf(bucket, o.Key, func(cur storage.ObjectInfo) error {
			if cur.ETag != o.ETag || !cur.ModTime.Equal(o.ModTime) {
				return errChanged
			}
			return nil
		})
		switch {
		case err == nil:
			stats.Expired++
		case errors.Is(err, storage.ErrObjectLocked):
			stats.Locked++
		case errors.Is(err, errChanged), errors.Is(err, storage.ErrNoSuchBucket):
		default:
			return err
		}
	case class != "" && effectiveClass(o) != class:
		err := w.Store.SetStorageClass(bucket, o.Key, o.ETag, class)
		if err != nil && !errors.Is(err, storage.ErrNoSuchBucket) {
			return err
		}
		if err == nil {
			stats.Transitioned++
		}
	}
	return nil
}

func effectiveClass(o storage.ObjectInfo) string {
	if o.StorageClass == "" {
		return storage.ClassStandard
	}
	return o.StorageClass
}

func (w *Worker) scanUploads(ctx context.Context, bucket string, rules []storage.LifecycleRule, stats *Stats) error {
	keyMarker, idMarker := "", ""
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		page, err := w.Store.ListUploads(bucket, "", "", keyMarker, idMarker, pageSize)
		if errors.Is(err, storage.ErrNoSuchBucket) {
			return nil
		}
		if err != nil {
			return err
		}
		now := w.now()
		for _, u := range page.Uploads {
			for _, r := range rules {
				if strings.HasPrefix(u.Key, r.Prefix) && due(now, u.Initiated, r.AbortUploadDays, nil) {
					err := w.Store.AbortUpload(bucket, u.Key, u.ID)
					if err == nil {
						stats.Aborted++
					} else if !errors.Is(err, storage.ErrNoSuchUpload) && !errors.Is(err, storage.ErrNoSuchBucket) {
						return err
					}
					break
				}
			}
		}
		if !page.IsTruncated {
			return nil
		}
		keyMarker, idMarker = page.NextKeyMarker, page.NextUploadIDMarker
	}
}
