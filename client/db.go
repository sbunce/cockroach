// Copyright 2015 The Cockroach Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License. See the AUTHORS file
// for names of contributors.
//
// Author: Peter Mattis (peter.mattis@gmail.com)

package client

import (
	"bytes"
	"encoding"
	"fmt"
	"log"
	"net/url"
	"strconv"
	"time"

	"github.com/cockroachdb/cockroach/proto"
	"github.com/cockroachdb/cockroach/testutils"
	gogoproto "github.com/gogo/protobuf/proto"
)

// KeyValue represents a single key/value pair and corresponding timestamp.
type KeyValue struct {
	Key       []byte
	Value     interface{}
	Timestamp time.Time
}

func (kv *KeyValue) String() string {
	switch t := kv.Value.(type) {
	case nil:
		return string(kv.Key) + "=nil"
	case []byte:
		return string(kv.Key) + "=" + string(t)
	case *int64:
		return string(kv.Key) + "=" + strconv.FormatInt(*t, 10)
	}
	return string(kv.Key) + fmt.Sprintf("=<ERROR:%T>", kv.Value)
}

// Exists returns true iff the value exists.
func (kv *KeyValue) Exists() bool {
	return kv.Value != nil
}

func (kv *KeyValue) setValue(v *proto.Value) {
	if v == nil {
		return
	}
	if v.Bytes != nil {
		kv.Value = v.Bytes
	} else if v.Integer != nil {
		kv.Value = v.Integer
	}
	if ts := v.Timestamp; ts != nil {
		sec := ts.WallTime / 1e9
		nsec := ts.WallTime % 1e9
		kv.Timestamp = time.Unix(sec, nsec)
	}
}

// ValueBytes returns the value as a byte slice. This method will panic if the
// value's type is not a byte slice.
func (kv *KeyValue) ValueBytes() []byte {
	return kv.Value.([]byte)
}

// ValueInt returns the value as an int64. This method will panic if the
// value's type is not an int64.
func (kv *KeyValue) ValueInt() int64 {
	return *kv.Value.(*int64)
}

// ValueProto parses the byte slice value as a proto message.
func (kv *KeyValue) ValueProto(msg gogoproto.Message) error {
	switch val := kv.Value.(type) {
	case nil:
		msg.Reset()
		return nil
	case []byte:
		return gogoproto.Unmarshal(val, msg)
	}
	return fmt.Errorf("unable to unmarshal proto: %T", kv.Value)
}

// Result holds the result for a single DB or Tx operation (e.g. Get, Put,
// etc).
type Result struct {
	calls int
	// Err contains any error encountered when performing the operation.
	Err error
	// Rows contains the key/value pairs for the operation. The number of rows
	// returned varies by operation. For Get, Put, CPut, Inc and Del the number
	// of rows returned is the number of keys operated on. For Scan the number of
	// rows returned is the number or rows matching the scan capped by the
	// maxRows parameter. For DelRange Rows is nil.
	Rows []KeyValue
}

func (r Result) Error() string {
	return r.Err.Error()
}

func (r Result) String() string {
	if r.Err != nil {
		return r.Err.Error()
	}
	var buf bytes.Buffer
	for i, row := range r.Rows {
		if i > 0 {
			buf.WriteString("\n")
		}
		fmt.Fprintf(&buf, "%d: %s", i, &row)
	}
	return buf.String()
}

// DB is a database handle to a single cockroach cluster. A DB is safe for
// concurrent use by multiple goroutines.
type DB struct {
	// B is a helper to make creating a new batch and performing an
	// operation on it easer:
	//
	//   err := db.Run(db.B.Put("a", "1").Put("b", "2"))
	B  batcher
	kv *KV
}

// Open creates a new database handle to the cockroach cluster specified by
// addr. The cluster is identified by a URL with the format:
//
//   (http|https|rpc|rpcs)://[<user>@]<host>:<port>
//
// The rpc and rpcs schemes use a variant of Go's builtin rpc library for
// communication with the cluster. This protocol is lower overhead and more
// efficient than http.
func Open(addr string) *DB {
	u, err := url.Parse(addr)
	if err != nil {
		log.Fatal(err)
	}

	// TODO(pmattis): This isn't right.
	ctx := testutils.NewTestBaseContext()

	var sender KVSender
	switch u.Scheme {
	case "http", "https":
		sender, err = NewHTTPSender(u.Host, ctx)
	case "rpc", "rpcs":
		sender, err = NewRPCSender(u.Host, ctx)
	default:
		log.Fatalf("unknown scheme: %s", u.Scheme)
	}
	if err != nil {
		log.Fatal(err)
	}

	kv := NewKV(nil, sender)
	kv.User = u.User.Username()
	return &DB{kv: kv}
}

// Get retrieves one or more keys. Each requested key will have a corresponding
// row in the returned Result.
//
//   r := db.Get("a", "b", "c")
//   // string(r.Rows[0].Key) == "a"
//   // string(r.Rows[1].Key) == "b"
//   // string(r.Rows[2].Key) == "c"
//
// A key can be either a byte slice, a string, a fmt.Stringer or an
// encoding.BinaryMarshaler.
func (db *DB) Get(keys ...interface{}) Result {
	return runOne(db, db.B.Get(keys...))
}

// Put sets the value for a key.
//
// The returned Result will contain a single row and Result.Err will indicate
// success or failure.
//
// A key can be either a byte slice, a string, a fmt.Stringer or an
// encoding.BinaryMarshaler. A value can be any key type or a proto.Message.
func (db *DB) Put(key, value interface{}) Result {
	return runOne(db, db.B.Put(key, value))
}

// CPut conditionally sets the value for a key if the existing value is equal
// to expValue. To conditionally set a value only if there is no existing entry
// pass nil for expValue.
//
// The returned Result will contain a single row and Result.Err will indicate
// success or failure.
//
// A key can be either a byte slice, a string, a fmt.Stringer or an
// encoding.BinaryMarshaler. A value can be any key type or a proto.Message.
func (db *DB) CPut(key, value, expValue interface{}) Result {
	return runOne(db, db.B.CPut(key, value, expValue))
}

// Inc increments the integer value at key. If the key does not exist it will
// be created with an initial value of 0 which will then be incremented. If the
// key exists but was set using Put or CPut an error will be returned.
//
// The returned Result will contain a single row and Result.Err will indicate
// success or failure.
//
// A key can be either a byte slice, a string, a fmt.Stringer or an
// encoding.BinaryMarshaler.
func (db *DB) Inc(key interface{}, value int64) Result {
	return runOne(db, db.B.Inc(key, value))
}

// Scan retrieves the rows between begin (inclusive) and end (exclusive).
//
// The returned Result will contain up to maxRows rows and Result.Err will
// indicate success or failure.
//
// A key can be either a byte slice, a string, a fmt.Stringer or an
// encoding.BinaryMarshaler.
func (db *DB) Scan(begin, end interface{}, maxRows int64) Result {
	return runOne(db, db.B.Scan(begin, end, maxRows))
}

// Del deletes one or more keys.
//
// Each key will have a corresponding row in the returned Result.
//
// A key can be either a byte slice, a string, a fmt.Stringer or an
// encoding.BinaryMarshaler.
func (db *DB) Del(keys ...interface{}) Result {
	return runOne(db, db.B.Del(keys...))
}

// DelRange deletes the rows between begin (inclusive) and end (exclusive).
//
// The returned Result will contain 0 rows and Result.Err will indicate success
// or failure.
//
// TODO(pmattis): Perhaps the result should return which rows were deleted.
//
// A key can be either a byte slice, a string, a fmt.Stringer or an
// encoding.BinaryMarshaler.
func (db *DB) DelRange(begin, end interface{}) Result {
	return runOne(db, db.B.DelRange(begin, end))
}

// Run executes the operations queued up within a batch. Before executing any
// of the operations the batch is first checked to see if there were any errors
// during its construction (e.g. failure to marshal a proto message).
//
// The operations within a batch are run in parallel and the order is
// non-deterministic. It is an unspecified behavior to modify and retrieve the
// same key within a batch.
//
// Upon completion, Batch.Results will contain the results for each
// operation. The order of the results matches the order the operations were
// added to the batch.
func (db *DB) Run(b *Batch) error {
	if err := b.prepare(); err != nil {
		return err
	}
	if err := db.kv.Run(b.calls...); err != nil {
		return err
	}
	return b.fillResults()
}

// Tx executes retryable in the context of a distributed transaction. The
// transaction is automatically aborted if retryable returns any error aside
// from recoverable internal errors, and is automatically committed
// otherwise. The retryable function should have no side effects which could
// cause problems in the event it must be run more than once.
//
// TODO(pmattis): Allow transaction options to be specified.
func (db *DB) Tx(retryable func(tx *Tx) error) error {
	return db.kv.RunTransaction(nil, func(txn *Txn) error {
		tx := &Tx{txn: txn}
		return retryable(tx)
	})
}

// Tx is an in-progress distributed database transaction. A Tx is not safe for
// concurrent use by multiple goroutines.
type Tx struct {
	// B is a helper to make creating a new batch and performing an
	// operation on it easer:
	//
	//   err := db.Tx(func(tx *Tx) error {
	//     return tx.Commit(tx.B.Put("a", "1").Put("b", "2"))
	//   })
	B   batcher
	txn *Txn
}

// Get retrieves one or more keys. Each requested key will have a corresponding
// row in the returned Result.
//
//   r := db.Get("a", "b", "c")
//   // string(r.Rows[0].Key) == "a"
//   // string(r.Rows[1].Key) == "b"
//   // string(r.Rows[2].Key) == "c"
//
// A key can be either a byte slice, a string, a fmt.Stringer or an
// encoding.BinaryMarshaler.
func (tx *Tx) Get(keys ...interface{}) Result {
	return runOne(tx, tx.B.Get(keys...))
}

// Put sets the value for a key.
//
// The returned Result will contain a single row and Result.Err will indicate
// success or failure.
//
// A key can be either a byte slice, a string, a fmt.Stringer or an
// encoding.BinaryMarshaler. A value can be any key type or a proto.Message.
func (tx *Tx) Put(key, value interface{}) Result {
	return runOne(tx, tx.B.Put(key, value))
}

// CPut conditionally sets the value for a key if the existing value is equal
// to expValue. To conditionally set a value only if there is no existing entry
// pass nil for expValue.
//
// The returned Result will contain a single row and Result.Err will indicate
// success or failure.
//
// A key can be either a byte slice, a string, a fmt.Stringer or an
// encoding.BinaryMarshaler. A value can be any key type or a proto.Message.
func (tx *Tx) CPut(key, value, expValue interface{}) Result {
	return runOne(tx, tx.B.CPut(key, value, expValue))
}

// Inc increments the integer value at key. If the key does not exist it will
// be created with an initial value of 0 which will then be incremented. If the
// key exists but was set using Put or CPut an error will be returned.
//
// The returned Result will contain a single row and Result.Err will indicate
// success or failure.
//
// A key can be either a byte slice, a string, a fmt.Stringer or an
// encoding.BinaryMarshaler.
func (tx *Tx) Inc(key interface{}, value int64) Result {
	return runOne(tx, tx.B.Inc(key, value))
}

// Scan retrieves the rows between begin (inclusive) and end (exclusive).
//
// The returned Result will contain up to maxRows rows and Result.Err will
// indicate success or failure.
//
// A key can be either a byte slice, a string, a fmt.Stringer or an
// encoding.BinaryMarshaler.
func (tx *Tx) Scan(begin, end interface{}, maxRows int64) Result {
	return runOne(tx, tx.B.Scan(begin, end, maxRows))
}

// Del deletes one or more keys.
//
// Each key will have a corresponding row in the returned Result.
//
// A key can be either a byte slice, a string, a fmt.Stringer or an
// encoding.BinaryMarshaler.
func (tx *Tx) Del(keys ...interface{}) Result {
	return runOne(tx, tx.B.Del(keys...))
}

// DelRange deletes the rows between begin (inclusive) and end (exclusive).
//
// The returned Result will contain 0 rows and Result.Err will indicate success
// or failure.
//
// A key can be either a byte slice, a string, a fmt.Stringer or an
// encoding.BinaryMarshaler.
func (tx *Tx) DelRange(begin, end interface{}) Result {
	return runOne(tx, tx.B.DelRange(begin, end))
}

// Run executes the operations queued up within a batch. Before executing any
// of the operations the batch is first checked to see if there were any errors
// during its construction (e.g. failure to marshal a proto message).
//
// The operations within a batch are run in parallel and the order is
// non-deterministic. It is an unspecified behavior to modify and retrieve the
// same key within a batch.
//
// Upon completion, Batch.Results will contain the results for each
// operation. The order of the results matches the order the operations were
// added to the batch.
func (tx *Tx) Run(b *Batch) error {
	if err := b.prepare(); err != nil {
		return err
	}
	if err := tx.txn.Run(b.calls...); err != nil {
		return err
	}
	return b.fillResults()
}

// Commit executes the operations queued up within a batch and commits the
// transaction. Explicitly committing a transaction is optional, but more
// efficient than relying on the implicit commit performed when the transaction
// function returns without error.
func (tx *Tx) Commit(b *Batch) error {
	args := &proto.EndTransactionRequest{Commit: true}
	reply := &proto.EndTransactionResponse{}
	b.calls = append(b.calls, Call{Args: args, Reply: reply})
	b.initResult(1, 0, nil)
	return tx.Run(b)
}

// Batch provides for the parallel execution of a number of database
// operations. Operations are added to the Batch and then the Batch is executed
// via either DB.Run, Tx.Run or Tx.Commit.
//
// TODO(pmattis): Allow a timestamp to be specified which is applied to all
// operations within the batch.
type Batch struct {
	// Results contains an entry for each operation added to the batch. The order
	// of the results matches the order the operations were added to the
	// batch. For example:
	//
	//   b := client.B.Put("a", "1").Put("b", "2")
	//   _ = db.Run(b)
	//   // string(b.Results[0].Rows[0].Key) == "a"
	//   // string(b.Results[1].Rows[0].Key) == "b"
	Results    []Result
	calls      []Call
	resultsBuf [8]Result
	rowsBuf    [8]KeyValue
	rowsIdx    int
}

func (b *Batch) prepare() error {
	for _, r := range b.Results {
		if err := r.Err; err != nil {
			return err
		}
	}
	return nil
}

func (b *Batch) initResult(calls, numRows int, err error) {
	r := Result{calls: calls, Err: err}
	if numRows > 0 {
		if b.rowsIdx+numRows <= len(b.rowsBuf) {
			r.Rows = b.rowsBuf[b.rowsIdx : b.rowsIdx+numRows]
			b.rowsIdx += numRows
		} else {
			r.Rows = make([]KeyValue, numRows)
		}
	}
	if b.Results == nil {
		b.Results = b.resultsBuf[0:0]
	}
	b.Results = append(b.Results, r)
}

func (b *Batch) fillResults() error {
	offset := 0
	for i := range b.Results {
		result := &b.Results[i]

		for k := 0; k < result.calls; k++ {
			call := b.calls[offset+k]

			switch t := call.Reply.(type) {
			case *proto.GetResponse:
				row := &result.Rows[k]
				row.Key = []byte(call.Args.(*proto.GetRequest).Key)
				row.setValue(t.Value)
			case *proto.PutResponse:
				row := &result.Rows[k]
				row.Key = []byte(call.Args.(*proto.PutRequest).Key)
				// TODO(pmattis): Don't set the value on error.
				row.setValue(&call.Args.(*proto.PutRequest).Value)
			case *proto.ConditionalPutResponse:
				row := &result.Rows[k]
				row.Key = []byte(call.Args.(*proto.ConditionalPutRequest).Key)
				// TODO(pmattis): Don't set the value on error.
				row.setValue(&call.Args.(*proto.ConditionalPutRequest).Value)
			case *proto.IncrementResponse:
				row := &result.Rows[k]
				row.Key = []byte(call.Args.(*proto.IncrementRequest).Key)
				// TODO(pmattis): Should IncrementResponse contain a
				// proto.Value so that the timestamp can be returned?
				row.Value = &t.NewValue
			case *proto.ScanResponse:
				result.Rows = make([]KeyValue, len(t.Rows))
				for j, kv := range t.Rows {
					row := &result.Rows[j]
					row.Key = kv.Key
					row.setValue(&kv.Value)
				}
			case *proto.DeleteResponse:
				row := &result.Rows[k]
				row.Key = []byte(call.Args.(*proto.DeleteRequest).Key)
			case *proto.DeleteRangeResponse:
			case *proto.EndTransactionResponse:
			default:
				return fmt.Errorf("unsupported reply: %T", call.Reply)
			}
		}
		offset += result.calls
	}
	return nil
}

// Get retrieves one or more keys. A new result will be appended to the batch
// and each requested key will have a corresponding row in the Result.
//
//   r := db.Get("a", "b", "c")
//   // string(r.Rows[0].Key) == "a"
//   // string(r.Rows[1].Key) == "b"
//   // string(r.Rows[2].Key) == "c"
//
// A key can be either a byte slice, a string, a fmt.Stringer or an
// encoding.BinaryMarshaler.
func (b *Batch) Get(keys ...interface{}) *Batch {
	var calls []Call
	for _, key := range keys {
		k, err := marshalKey(key)
		if err != nil {
			b.initResult(0, len(keys), err)
			break
		}
		calls = append(calls, Get(proto.Key(k)))
	}
	b.calls = append(b.calls, calls...)
	b.initResult(len(calls), len(calls), nil)
	return b
}

// Put sets the value for a key.
//
// A new result will be appended to the batch which will contain a single row
// and Result.Err will indicate success or failure.
//
// A key can be either a byte slice, a string, a fmt.Stringer or an
// encoding.BinaryMarshaler. A value can be any key type or a proto.Message.
func (b *Batch) Put(key, value interface{}) *Batch {
	k, err := marshalKey(key)
	if err != nil {
		b.initResult(0, 1, err)
		return b
	}
	v, err := marshalValue(value)
	if err != nil {
		b.initResult(0, 1, err)
		return b
	}
	b.calls = append(b.calls, Put(proto.Key(k), v))
	b.initResult(1, 1, nil)
	return b
}

// CPut conditionally sets the value for a key if the existing value is equal
// to expValue. To conditionally set a value only if there is no existing entry
// pass nil for expValue.
//
// A new result will be appended to the batch which will contain a single row
// and Result.Err will indicate success or failure.
//
// A key can be either a byte slice, a string, a fmt.Stringer or an
// encoding.BinaryMarshaler. A value can be any key type or a proto.Message.
func (b *Batch) CPut(key, value, expValue interface{}) *Batch {
	k, err := marshalKey(key)
	if err != nil {
		b.initResult(0, 1, err)
		return b
	}
	v, err := marshalValue(value)
	if err != nil {
		b.initResult(0, 1, err)
		return b
	}
	ev, err := marshalValue(expValue)
	if err != nil {
		b.initResult(0, 1, err)
		return b
	}
	b.calls = append(b.calls, ConditionalPut(proto.Key(k), v, ev))
	b.initResult(1, 1, nil)
	return b
}

// Inc increments the integer value at key. If the key does not exist it will
// be created with an initial value of 0 which will then be incremented. If the
// key exists but was set using Put or CPut an error will be returned.
//
// A new result will be appended to the batch which will contain a single row
// and Result.Err will indicate success or failure.
//
// A key can be either a byte slice, a string, a fmt.Stringer or an
// encoding.BinaryMarshaler.
func (b *Batch) Inc(key interface{}, value int64) *Batch {
	k, err := marshalKey(key)
	if err != nil {
		b.initResult(0, 1, err)
		return b
	}
	b.calls = append(b.calls, Increment(proto.Key(k), value))
	b.initResult(1, 1, nil)
	return b
}

// Scan retrieves the rows between begin (inclusive) and end (exclusive).
//
// A new result will be appended to the batch which will contain up to maxRows
// rows and Result.Err will indicate success or failure.
//
// A key can be either a byte slice, a string, a fmt.Stringer or an
// encoding.BinaryMarshaler.
func (b *Batch) Scan(s, e interface{}, maxRows int64) *Batch {
	begin, err := marshalKey(s)
	if err != nil {
		b.initResult(0, 0, err)
		return b
	}
	end, err := marshalKey(e)
	if err != nil {
		b.initResult(0, 0, err)
		return b
	}
	b.calls = append(b.calls, Scan(proto.Key(begin), proto.Key(end), maxRows))
	b.initResult(1, 0, nil)
	return b
}

// Del deletes one or more keys.
//
// A new result will be appended to the batch and each key will have a
// corresponding row in the returned Result.
//
// A key can be either a byte slice, a string, a fmt.Stringer or an
// encoding.BinaryMarshaler.
func (b *Batch) Del(keys ...interface{}) *Batch {
	var calls []Call
	for _, key := range keys {
		k, err := marshalKey(key)
		if err != nil {
			b.initResult(0, len(keys), err)
			return b
		}
		calls = append(calls, Delete(proto.Key(k)))
	}
	b.calls = append(b.calls, calls...)
	b.initResult(len(calls), len(calls), nil)
	return b
}

// DelRange deletes the rows between begin (inclusive) and end (exclusive).
//
// A new result will be appended to the batch which will contain 0 rows and
// Result.Err will indicate success or failure.
//
// A key can be either a byte slice, a string, a fmt.Stringer or an
// encoding.BinaryMarshaler.
func (b *Batch) DelRange(s, e interface{}) *Batch {
	begin, err := marshalKey(s)
	if err != nil {
		b.initResult(0, 0, err)
		return b
	}
	end, err := marshalKey(e)
	if err != nil {
		b.initResult(0, 0, err)
		return b
	}
	b.calls = append(b.calls, DeleteRange(proto.Key(begin), proto.Key(end)))
	b.initResult(1, 0, nil)
	return b
}

type batcher struct{}

func (b batcher) Get(keys ...interface{}) *Batch {
	return (&Batch{}).Get(keys...)
}

func (b batcher) Put(key, value interface{}) *Batch {
	return (&Batch{}).Put(key, value)
}

func (b batcher) CPut(key, value, expValue interface{}) *Batch {
	return (&Batch{}).CPut(key, value, expValue)
}

func (b batcher) Inc(key interface{}, value int64) *Batch {
	return (&Batch{}).Inc(key, value)
}

func (b batcher) Scan(begin, end interface{}, maxRows int64) *Batch {
	return (&Batch{}).Scan(begin, end, maxRows)
}

func (b batcher) Del(keys ...interface{}) *Batch {
	return (&Batch{}).Del(keys...)
}

func (b batcher) DelRange(begin, end interface{}) *Batch {
	return (&Batch{}).DelRange(begin, end)
}

func marshalKey(k interface{}) ([]byte, error) {
	switch t := k.(type) {
	case encoding.BinaryMarshaler:
		return t.MarshalBinary()
	case fmt.Stringer:
		return []byte(t.String()), nil
	case string:
		return []byte(t), nil
	case []byte:
		return t, nil
	case proto.Key:
		return []byte(t), nil
	}
	return nil, fmt.Errorf("unable to marshal key: %T", k)
}

func marshalValue(v interface{}) ([]byte, error) {
	switch t := v.(type) {
	case encoding.BinaryMarshaler:
		return t.MarshalBinary()
	case gogoproto.Message:
		return gogoproto.Marshal(t)
	case fmt.Stringer:
		return []byte(t.String()), nil
	case string:
		return []byte(t), nil
	case []byte:
		return t, nil
	case nil:
		return nil, nil
	}
	return nil, fmt.Errorf("unable to marshal value: %T", v)
}

type runner interface {
	Run(b *Batch) error
}

func runOne(r runner, b *Batch) Result {
	if err := r.Run(b); err != nil {
		return Result{Err: err}
	}
	return b.Results[0]
}
