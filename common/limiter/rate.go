package limiter

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"golang.org/x/time/rate"
)

type Writer struct {
	writer  buf.Writer
	limiter *rate.Limiter
	w       io.Writer
}

type Reader struct {
	reader  buf.Reader
	limiter *rate.Limiter
}

func (l *Limiter) RateWriter(writer buf.Writer, limiter *rate.Limiter) buf.Writer {
	return &Writer{
		writer:  writer,
		limiter: limiter,
	}
}

func (l *Limiter) RateReader(reader buf.Reader, limiter *rate.Limiter) buf.Reader {
	return &Reader{
		reader:  reader,
		limiter: limiter,
	}
}

func (w *Writer) Close() error {
	return common.Close(w.writer)
}

func (w *Writer) WriteMultiBuffer(mb buf.MultiBuffer) error {
	ctx := context.Background()
	w.limiter.WaitN(ctx, int(mb.Len()))
	return w.writer.WriteMultiBuffer(mb)
}

func (r *Reader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.reader.ReadMultiBuffer()
	if err != nil || mb.IsEmpty() {
		return mb, err
	}
	ctx := context.Background()
	r.limiter.WaitN(ctx, int(mb.Len()))
	return mb, nil
}

// GuardReader / GuardWriter 周期性复查连接的在线名额，被挤出且名额已满时
// 返回错误，促使 xray 关闭连接，从而让超限设备的既有长连接也被强制断开。
//
// 方向语义（refresh 标志）：只有上行方向（客户端发来的数据）才能证明该 IP
// 的客户端仍然存活，允许续期在线时间；下行方向（远端推送的数据）只做核查
// 不续期，避免客户端异常离线后残留连接被远端数据无限"续命"、名额永不释放。

type guardState struct {
	l       *Limiter
	tag     string
	userKey string
	ip      string
	refresh bool
	next    int64
}

func (g *guardState) check() error {
	if now := time.Now().Unix(); now >= g.next {
		g.next = now + onlineTouchSec
		var allowed bool
		if g.refresh {
			allowed = g.l.EnsureOnline(g.tag, g.userKey, g.ip)
		} else {
			allowed = g.l.VerifyOnline(g.tag, g.userKey, g.ip)
		}
		if !allowed {
			return errDeviceLimited
		}
	}
	return nil
}

var errDeviceLimited = errors.New("device limit exceeded, connection closed by limiter")

type GuardReader struct {
	reader buf.Reader
	guardState
}

type GuardWriter struct {
	writer buf.Writer
	guardState
}

// GuardReader 上行方向（读客户端数据）：核查并续期。
func (l *Limiter) GuardReader(reader buf.Reader, tag, userKey, ip string) buf.Reader {
	return &GuardReader{reader: reader, guardState: guardState{l: l, tag: tag, userKey: userKey, ip: ip, refresh: true}}
}

// GuardWriter 下行方向（向客户端写数据）：只核查不续期。
func (l *Limiter) GuardWriter(writer buf.Writer, tag, userKey, ip string) buf.Writer {
	return &GuardWriter{writer: writer, guardState: guardState{l: l, tag: tag, userKey: userKey, ip: ip}}
}

// GuardUplinkWriter 上行方向的写端（承载客户端→远端的数据）：核查并续期。
func (l *Limiter) GuardUplinkWriter(writer buf.Writer, tag, userKey, ip string) buf.Writer {
	return &GuardWriter{writer: writer, guardState: guardState{l: l, tag: tag, userKey: userKey, ip: ip, refresh: true}}
}

func (r *GuardReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	return r.reader.ReadMultiBuffer()
}

func (w *GuardWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if err := w.check(); err != nil {
		buf.ReleaseMulti(mb)
		return err
	}
	return w.writer.WriteMultiBuffer(mb)
}

func (w *GuardWriter) Close() error {
	return common.Close(w.writer)
}

func (r *Reader) ReadMultiBufferTimeout(timeout time.Duration) (buf.MultiBuffer, error) {
	// If underlying reader supports timeout, use it; otherwise fallback to non-timeout read.
	type timeoutReader interface {
		ReadMultiBufferTimeout(time.Duration) (buf.MultiBuffer, error)
	}
	if tr, ok := r.reader.(timeoutReader); ok {
		mb, err := tr.ReadMultiBufferTimeout(timeout)
		if err != nil || mb.IsEmpty() {
			return mb, err
		}
		ctx := context.Background()
		r.limiter.WaitN(ctx, int(mb.Len()))
		return mb, nil
	}
	mb, err := r.reader.ReadMultiBuffer()
	if err != nil || mb.IsEmpty() {
		return mb, err
	}
	ctx := context.Background()
	r.limiter.WaitN(ctx, int(mb.Len()))
	return mb, nil
}
