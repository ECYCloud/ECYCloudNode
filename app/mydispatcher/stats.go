package mydispatcher

import (
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/features/stats"
)

type SizeStatWriter struct {
	Counter stats.Counter
	Writer  buf.Writer
	Record  func(int64) error
}

func (w *SizeStatWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if w.Record != nil {
		if err := w.Record(int64(mb.Len())); err != nil {
			buf.ReleaseMulti(mb)
			return err
		}
	}
	if w.Counter != nil {
		w.Counter.Add(int64(mb.Len()))
	}
	return w.Writer.WriteMultiBuffer(mb)
}

func (w *SizeStatWriter) Close() error {
	return common.Close(w.Writer)
}

func (w *SizeStatWriter) Interrupt() {
	common.Interrupt(w.Writer)
}

// 官方 dispatcher 的上行通过 Reader 转发，必须在交付出站前落盘。
type SizeStatReader struct {
	Reader buf.Reader
	Record func(int64) error
}

func (r *SizeStatReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.Reader.ReadMultiBuffer()
	if !mb.IsEmpty() {
		if recordErr := r.Record(int64(mb.Len())); recordErr != nil {
			buf.ReleaseMulti(mb)
			return nil, recordErr
		}
	}
	return mb, err
}

func (r *SizeStatReader) Interrupt() {
	common.Interrupt(r.Reader)
}
