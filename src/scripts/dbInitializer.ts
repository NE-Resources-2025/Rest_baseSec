import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';

const prisma = new PrismaClient();

async function initializeDatabase(): Promise<void> {
  try {
    console.log('Initializing database...');

    // Create admin user if not exists
    const adminEmail = 'user@admin.com';
    const adminExists = await prisma.user.findUnique({ where: { email: adminEmail } });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash('adminEdwige123!', 10);
      await prisma.user.create({
        data: {
          name: 'Admin User',
          email: adminEmail,
          password: hashedPassword,
          role: 'admin',
          isVerified: true,
        },
      });
      console.log('Admin user created');
    }

    
    console.log('Database initialized successfully');
  } catch (error) {
    console.error('Database initialization error:', error);
  } finally {
    await prisma.$disconnect();
  }
}

initializeDatabase();