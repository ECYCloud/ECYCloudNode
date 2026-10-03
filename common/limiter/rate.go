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
	limiter *Limiter
	tag     string
	userKey string
	w       io.Writer
}

type Reader struct {
	reader  buf.Reader
	limiter *Limiter
	tag     string
	userKey string
}

func (l *Limiter) RateWriter(writer buf.Writer, tag, userKey string) buf.Writer {
	return &Writer{
		writer:  writer,
		limiter: l,
		tag:     tag,
		userKey: userKey,
	}
}

func WaitN(ctx context.Context, limiter *rate.Limiter, n int) error {
	if limiter.Limit() == rate.Inf || n <= 0 {
		return limiter.WaitN(ctx, n)
	}
	for n > 0 {
		part := min(n, max(limiter.Burst(), 1))
		if err := limiter.WaitN(ctx, part); err != nil {
			return err
		}
		n -= part
	}
	return nil
}

func (l *Limiter) RateReader(reader buf.Reader, tag, userKey string) buf.Reader {
	return &Reader{
		reader:  reader,
		limiter: l,
		tag:     tag,
		userKey: userKey,
	}
}

func (w *Writer) Close() error {
	return common.Close(w.writer)
}

func (w *Writer) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if bucket := w.limiter.rateBucket(w.tag, w.userKey); bucket != nil {
		if err := WaitN(context.Background(), bucket, int(mb.Len())); err != nil {
			buf.ReleaseMulti(mb)
			return err
		}
	}
	if !w.limiter.AuthorizationAllowed(w.tag, w.userKey) {
		buf.ReleaseMulti(mb)
		return errors.New("user authorization expired or revoked")
	}
	return w.writer.WriteMultiBuffer(mb)
}

func (r *Reader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.reader.ReadMultiBuffer()
	return r.wait(mb, err)
}

func (r *Reader) Interrupt() {
	common.Interrupt(r.reader)
}

func (r *Reader) wait(mb buf.MultiBuffer, err error) (buf.MultiBuffer, error) {
	if !mb.IsEmpty() {
		if bucket := r.limiter.rateBucket(r.tag, r.userKey); bucket != nil {
			if waitErr := WaitN(context.Background(), bucket, int(mb.Len())); waitErr != nil {
				buf.ReleaseMulti(mb)
				return nil, waitErr
			}
		}
		if !r.limiter.AuthorizationAllowed(r.tag, r.userKey) {
			buf.ReleaseMulti(mb)
			return nil, errors.New("user authorization expired or revoked")
		}
	}
	return mb, err
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
	if !g.l.AuthorizationAllowed(g.tag, g.userKey) {
		return errors.New("user authorization expired or revoked")
	}
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
	mb, err := r.reader.ReadMultiBuffer()
	if err == nil {
		if rejected := r.check(); rejected != nil {
			buf.ReleaseMulti(mb)
			return nil, rejected
		}
	}
	return mb, err
}

func (r *GuardReader) Interrupt() {
	common.Interrupt(r.reader)
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
		return r.wait(mb, err)
	}
	return r.ReadMultiBuffer()
}
