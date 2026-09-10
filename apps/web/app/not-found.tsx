// 404 — đường dẫn không tồn tại
export default function NotFound() {
  return (
    <main className="page">
      <h1>404 — không tìm thấy đường dẫn</h1>
      <p className="sub">
        Địa chỉ bạn truy cập không tồn tại. Quay lại trang Trạng thái để tiếp
        tục.
      </p>
      <a className="btn primary" href="/">
        Về trang Trạng thái
      </a>
    </main>
  );
}
