$(function () {
    // --- Code cho Login Modal (giữ nguyên từ trước) ---
    $('body').on('click', '#loginModalButton', function (event) {
        event.preventDefault();
        var returnUrl = $(this).data('return-url') || window.location.pathname + window.location.search;
        var url = "/Account/LoginModal?returnUrl=" + encodeURIComponent(returnUrl);

        if ($('#loginModalInstance').length === 0) {
            $('#loginModalPlaceholder').html('<div class="modal fade" id="loginModalInstance" tabindex="-1" aria-labelledby="loginModalLabel" aria-hidden="true"></div>');
        }
        var $modalInstance = $('#loginModalInstance');
        $modalInstance.load(url, function () {
            var modal = new bootstrap.Modal($modalInstance[0]);
            modal.show();
        });
    });

    $('body').on('submit', '#loginFormModal', function (event) {
        // ... (code submit login form giữ nguyên) ...
        event.preventDefault();
        var form = $(this);
        if (!form.valid()) { return; }
        var submitButton = form.find('button[type="submit"]');
        var originalButtonText = submitButton.html();
        submitButton.html('<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Đang xử lý...').prop('disabled', true);
        $.ajax({
            url: form.attr('action'),
            method: form.attr('method'),
            data: form.serialize(),
            success: function (response) {
                if (response.success) {
                    if (response.redirectUrl) { window.location.href = response.redirectUrl; }
                    else { window.location.reload(); }
                } else {
                    $('#loginModalInstance').html(response);
                }
            },
            error: function (xhr, status, error) {
                console.error("AJAX Error: ", status, error, xhr.responseText);
                alert("Đã xảy ra lỗi trong quá trình đăng nhập. Vui lòng thử lại.");
                submitButton.html(originalButtonText).prop('disabled', false);
            }
        });
    });

    $('body').on('hidden.bs.modal', '#loginModalInstance', function () {
        $(this).empty();
    });


    // --- CODE MỚI CHO REGISTER MODAL ---
    $('body').on('click', '#registerModalButton', function (event) {
        event.preventDefault();
        var returnUrl = $(this).data('return-url') || window.location.pathname + window.location.search;
        var url = "/Account/RegisterModal?returnUrl=" + encodeURIComponent(returnUrl); // Action mới

        // Tạo modal container nếu chưa có
        if ($('#registerModalInstance').length === 0) {
            $('#registerModalPlaceholder').html('<div class="modal fade" id="registerModalInstance" tabindex="-1" aria-labelledby="registerModalLabel" aria-hidden="true"></div>');
        }

        var $modalInstance = $('#registerModalInstance');

        // Tải nội dung form vào modal
        $modalInstance.load(url, function () {
            var modal = new bootstrap.Modal($modalInstance[0]);
            modal.show();
        });
    });

    // Xử lý submit form đăng ký bằng AJAX
    $('body').on('submit', '#registerFormModal', function (event) {
        event.preventDefault();
        var form = $(this);

        if (!form.valid()) { // Cần jquery.validate.js
            return;
        }

        var submitButton = form.find('button[type="submit"]');
        var originalButtonText = submitButton.html();
        submitButton.html('<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Đang xử lý...').prop('disabled', true);

        $.ajax({
            url: form.attr('action'),
            method: form.attr('method'),
            data: form.serialize(),
            success: function (response) {
                if (response.success && response.redirectUrl) {
                    // Đăng ký bước 1 thành công, chuyển hướng đến trang hoàn tất
                    window.location.href = response.redirectUrl;
                } else {
                    // Nếu có lỗi ngay ở bước 1 (ví dụ email đã tồn tại), server trả về partial view với lỗi
                    $('#registerModalInstance').html(response);
                    // Parse lại validation cho form mới
                    var newForm = $('#registerFormModal');
                    if (newForm.length && typeof $.validator !== 'undefined' && typeof $.validator.unobtrusive !== 'undefined') {
                        newForm.removeData('validator');
                        newForm.removeData('unobtrusiveValidation');
                        $.validator.unobtrusive.parse(newForm);
                    }
                }
            },
            error: function (xhr, status, error) {
                console.error("AJAX Error: ", status, error, xhr.responseText);
                alert("Đã xảy ra lỗi trong quá trình đăng ký. Vui lòng thử lại.");
                submitButton.html(originalButtonText).prop('disabled', false);
            }
        });
    });

    // Tùy chọn: Dọn dẹp modal đăng ký khi nó bị đóng
    $('body').on('hidden.bs.modal', '#registerModalInstance', function () {
        $(this).empty();
    });

});