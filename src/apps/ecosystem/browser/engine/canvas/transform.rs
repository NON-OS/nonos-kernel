pub struct CanvasTransform {
    pub a: f64,
    pub b: f64,
    pub c: f64,
    pub d: f64,
    pub e: f64,
    pub f: f64,
}

impl CanvasTransform {
    pub fn identity() -> Self {
        Self { a: 1.0, b: 0.0, c: 0.0, d: 1.0, e: 0.0, f: 0.0 }
    }

    pub fn translate(&mut self, tx: f64, ty: f64) {
        self.e += tx;
        self.f += ty;
    }

    pub fn scale(&mut self, sx: f64, sy: f64) {
        self.a *= sx;
        self.d *= sy;
    }

    pub fn rotate(&mut self, angle: f64) {
        let cos = libm::cos(angle);
        let sin = libm::sin(angle);
        let a = self.a * cos + self.c * sin;
        let b = self.b * cos + self.d * sin;
        let c = self.a * -sin + self.c * cos;
        let d = self.b * -sin + self.d * cos;
        self.a = a;
        self.b = b;
        self.c = c;
        self.d = d;
    }

    pub fn set_transform(&mut self, a: f64, b: f64, c: f64, d: f64, e: f64, f: f64) {
        self.a = a;
        self.b = b;
        self.c = c;
        self.d = d;
        self.e = e;
        self.f = f;
    }

    pub fn reset(&mut self) {
        *self = Self::identity();
    }

    pub fn transform_point(&self, x: f64, y: f64) -> (f64, f64) {
        (self.a * x + self.c * y + self.e, self.b * x + self.d * y + self.f)
    }
}
